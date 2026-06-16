#!/usr/bin/env python3
"""
dns_manager.py

Idempotently create or update Cloudflare DNS records from a declarative YAML
file. Reads the API token from CLOUDFLARE_API_TOKEN (never from the records
file or command-line arguments).

Usage:
    python dns_manager.py --records records.yaml --dry-run
    python dns_manager.py --records records.yaml
"""

import argparse
import os
import sys
import json
from typing import Optional

try:
    import yaml
except ImportError:
    # Provide a helpful error before crashing
    sys.exit(
        "ERROR: PyYAML is not installed.\n"
        "Run: pip install pyyaml requests"
    )

try:
    import requests
except ImportError:
    sys.exit(
        "ERROR: requests is not installed.\n"
        "Run: pip install pyyaml requests"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CF_API_BASE = "https://api.cloudflare.com/client/v4"

# Record types that have a "priority" field in the Cloudflare API
PRIORITY_TYPES = {"MX", "SRV", "URI"}


# ---------------------------------------------------------------------------
# Cloudflare API helpers
# ---------------------------------------------------------------------------

def make_headers(token: str) -> dict:
    """Build the Authorization header required by every CF API request."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def cf_get(path: str, token: str, params: Optional[dict] = None) -> dict:
    """
    Perform a GET request against the Cloudflare API.
    Raises RuntimeError on HTTP or API-level errors.
    """
    url = f"{CF_API_BASE}{path}"
    response = requests.get(url, headers=make_headers(token), params=params, timeout=15)
    response.raise_for_status()
    data = response.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        raise RuntimeError(f"Cloudflare API error on GET {path}: {errors}")
    return data


def cf_post(path: str, token: str, payload: dict) -> dict:
    """
    Perform a POST request (create a new record) against the Cloudflare API.
    Raises RuntimeError on HTTP or API-level errors.
    """
    url = f"{CF_API_BASE}{path}"
    response = requests.post(
        url, headers=make_headers(token), json=payload, timeout=15
    )
    response.raise_for_status()
    data = response.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        raise RuntimeError(f"Cloudflare API error on POST {path}: {errors}")
    return data


def cf_put(path: str, token: str, payload: dict) -> dict:
    """
    Perform a PUT request (replace an existing record) against the CF API.
    Cloudflare uses PUT (not PATCH) to fully replace a record by ID.
    Raises RuntimeError on HTTP or API-level errors.
    """
    url = f"{CF_API_BASE}{path}"
    response = requests.put(
        url, headers=make_headers(token), json=payload, timeout=15
    )
    response.raise_for_status()
    data = response.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        raise RuntimeError(f"Cloudflare API error on PUT {path}: {errors}")
    return data


# ---------------------------------------------------------------------------
# DNS record fetching
# ---------------------------------------------------------------------------

def fetch_existing_records(zone_id: str, token: str) -> list[dict]:
    """
    Retrieve all DNS records for the zone, handling Cloudflare's pagination
    (up to 1000 records per page, iterate until all pages are fetched).
    """
    all_records = []
    page = 1
    per_page = 100  # CF max is 1000; 100 is a safe, readable default

    while True:
        data = cf_get(
            f"/zones/{zone_id}/dns_records",
            token,
            params={"page": page, "per_page": per_page},
        )
        records = data.get("result", [])
        all_records.extend(records)

        result_info = data.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1

    return all_records


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def find_matching_record(
    existing: list[dict], rtype: str, name: str
) -> Optional[dict]:
    """
    Find an existing record that matches on (type, name).

    For MX records, there can be multiple records with the same name but
    different values (e.g., multiple mail servers). This function returns the
    first match — the caller handles deduplication logic.
    """
    rtype_upper = rtype.upper()
    for record in existing:
        if record["type"].upper() == rtype_upper and record["name"] == name:
            return record
    return None


def records_differ(existing: dict, desired: dict) -> bool:
    """
    Return True if any meaningful field differs between the existing CF record
    and our desired state. Only compares fields we manage — we deliberately
    ignore CF-managed fields like 'id', 'created_on', 'modified_on'.
    """
    # Compare content (the record value)
    if existing.get("content") != desired.get("content"):
        return True
    # Compare TTL (CF represents "auto" as 1)
    if existing.get("ttl") != desired.get("ttl", 1):
        return True
    # Compare proxied flag (only TXT/MX/CNAME etc. support this)
    if existing.get("proxied") != desired.get("proxied", False):
        return True
    # Compare priority for types that support it (e.g., MX)
    if desired.get("type", "").upper() in PRIORITY_TYPES:
        if existing.get("priority") != desired.get("priority"):
            return True
    return False


# ---------------------------------------------------------------------------
# Core upsert logic
# ---------------------------------------------------------------------------

def build_cf_payload(record: dict) -> dict:
    """
    Convert a record from our YAML schema into the payload format the
    Cloudflare API expects.
    """
    payload = {
        "type": record["type"].upper(),
        "name": record["name"],
        "content": record["content"],
        "ttl": record.get("ttl", 1),         # 1 = Cloudflare "Auto" TTL
        "proxied": record.get("proxied", False),
    }
    # Add priority for record types that require it
    if record["type"].upper() in PRIORITY_TYPES:
        payload["priority"] = record.get("priority", 10)
    return payload


def upsert_record(
    zone_id: str,
    token: str,
    desired: dict,
    existing_records: list[dict],
    dry_run: bool,
    verbose: bool,
) -> str:
    """
    Upsert a single DNS record:
    - If no matching record exists → CREATE (POST)
    - If a match exists and values differ → UPDATE (PUT)
    - If a match exists and values are identical → SKIP (idempotent)

    Returns a status string: 'created', 'updated', or 'skipped'.
    """
    rtype = desired["type"].upper()
    name = desired["name"]
    content = desired["content"]

    existing = find_matching_record(existing_records, rtype, name)
    payload = build_cf_payload(desired)

    if existing is None:
        # Record does not exist — create it
        print(f"  [CREATE] {rtype} {name} -> {content!r}")
        if not dry_run:
            result = cf_post(f"/zones/{zone_id}/dns_records", token, payload)
            if verbose:
                print(f"    Response: {json.dumps(result.get('result'), indent=2)}")
        return "created"

    if records_differ(existing, payload):
        # Record exists but values differ — update it
        record_id = existing["id"]
        print(f"  [UPDATE] {rtype} {name}")
        print(f"    old content: {existing.get('content')!r}")
        print(f"    new content: {content!r}")
        if not dry_run:
            result = cf_put(
                f"/zones/{zone_id}/dns_records/{record_id}", token, payload
            )
            if verbose:
                print(f"    Response: {json.dumps(result.get('result'), indent=2)}")
        return "updated"

    # Record exists and is already correct — nothing to do
    print(f"  [SKIP]   {rtype} {name} (already correct)")
    return "skipped"


# ---------------------------------------------------------------------------
# YAML loading and validation
# ---------------------------------------------------------------------------

REQUIRED_RECORD_KEYS = {"type", "name", "content"}


def load_records_file(path: str) -> dict:
    """
    Load and minimally validate the records YAML file.
    Expected top-level keys: zone_id, records (list).
    """
    if not os.path.exists(path):
        sys.exit(f"ERROR: Records file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            sys.exit(f"ERROR: Failed to parse YAML: {exc}")

    if not isinstance(data, dict):
        sys.exit("ERROR: Records file must be a YAML mapping at the top level.")

    if "zone_id" not in data:
        sys.exit("ERROR: 'zone_id' is required in the records file.")

    if "records" not in data or not isinstance(data["records"], list):
        sys.exit("ERROR: 'records' must be a list in the records file.")

    for i, record in enumerate(data["records"]):
        missing = REQUIRED_RECORD_KEYS - record.keys()
        if missing:
            sys.exit(
                f"ERROR: Record #{i + 1} is missing required keys: {missing}\n"
                f"  Record: {record}"
            )

    return data


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Idempotently manage Cloudflare DNS records from a YAML file.\n"
            "Reads the API token from the CLOUDFLARE_API_TOKEN environment variable."
        )
    )
    parser.add_argument(
        "--records",
        required=True,
        help="Path to the YAML file defining desired DNS records.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned changes without making any API calls that modify data.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full API response payloads for each change.",
    )
    args = parser.parse_args()

    # --- Retrieve API token from environment (never from CLI or file) ---
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        sys.exit(
            "ERROR: CLOUDFLARE_API_TOKEN environment variable is not set.\n"
            "Generate a token at: https://dash.cloudflare.com/profile/api-tokens\n"
            "Required permission: Zone:DNS:Edit"
        )

    # --- Load desired state from file ---
    config = load_records_file(args.records)
    zone_id = config["zone_id"]
    desired_records = config["records"]

    if args.dry_run:
        print("=== DRY RUN — no changes will be made ===\n")

    print(f"Zone ID : {zone_id}")
    print(f"Records : {len(desired_records)} desired")
    print()

    # --- Fetch current state from Cloudflare ---
    print("Fetching existing DNS records from Cloudflare...")
    try:
        existing_records = fetch_existing_records(zone_id, token)
    except requests.HTTPError as exc:
        # A 401 here almost always means a bad or missing token
        if exc.response is not None and exc.response.status_code == 401:
            sys.exit(
                "ERROR: Cloudflare returned 401 Unauthorized.\n"
                "Check that CLOUDFLARE_API_TOKEN is correct and has Zone:DNS:Edit permission."
            )
        sys.exit(f"ERROR: HTTP error fetching records: {exc}")
    except RuntimeError as exc:
        sys.exit(f"ERROR: {exc}")

    print(f"Found {len(existing_records)} existing record(s).\n")
    print("Processing desired records:")

    # --- Upsert each desired record ---
    counts = {"created": 0, "updated": 0, "skipped": 0}

    for record in desired_records:
        try:
            status = upsert_record(
                zone_id=zone_id,
                token=token,
                desired=record,
                existing_records=existing_records,
                dry_run=args.dry_run,
                verbose=args.verbose,
            )
            counts[status] += 1
        except requests.HTTPError as exc:
            # Log the error but continue processing remaining records
            print(f"  [ERROR]  {record.get('type')} {record.get('name')}: HTTP {exc}")
        except RuntimeError as exc:
            print(f"  [ERROR]  {record.get('type')} {record.get('name')}: {exc}")

    # --- Summary ---
    print()
    if args.dry_run:
        print("=== DRY RUN complete (no changes applied) ===")
    else:
        print("=== Done ===")
    print(
        f"  Created : {counts['created']}\n"
        f"  Updated : {counts['updated']}\n"
        f"  Skipped : {counts['skipped']} (already correct)"
    )


if __name__ == "__main__":
    main()
