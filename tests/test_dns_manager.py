"""
tests/test_dns_manager.py

Unit tests for dns_manager.py.

All Cloudflare HTTP calls are mocked — no network access or credentials needed.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch, call
import os

# ---------------------------------------------------------------------------
# Ensure the repo root is on sys.path so we can import dns_manager directly.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import dns_manager  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cf_record(rtype, name, content, ttl=1, proxied=False, priority=None, record_id="rec-1"):
    """Build a fake Cloudflare API record dict."""
    rec = {
        "id": record_id,
        "type": rtype.upper(),
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied,
    }
    if priority is not None:
        rec["priority"] = priority
    return rec


def _cf_response(result, total_pages=1):
    """Wrap a result list in the CF API envelope."""
    return {
        "success": True,
        "result": result,
        "result_info": {"total_pages": total_pages, "page": 1},
    }


# ===========================================================================
# make_headers
# ===========================================================================

class TestMakeHeaders(unittest.TestCase):
    def test_bearer_token_injected(self):
        h = dns_manager.make_headers("tok-abc")
        self.assertEqual(h["Authorization"], "Bearer tok-abc")
        self.assertEqual(h["Content-Type"], "application/json")


# ===========================================================================
# find_matching_record
# ===========================================================================

class TestFindMatchingRecord(unittest.TestCase):

    def setUp(self):
        self.existing = [
            _cf_record("TXT", "example.com", "v=spf1 -all", record_id="r1"),
            _cf_record("MX", "example.com", "mail.example.com", priority=10, record_id="r2"),
            _cf_record("CNAME", "mail._domainkey.example.com", "mail.provider.com", record_id="r3"),
        ]

    def test_finds_txt_by_type_and_name(self):
        match = dns_manager.find_matching_record(self.existing, "TXT", "example.com")
        self.assertIsNotNone(match)
        self.assertEqual(match["id"], "r1")

    def test_finds_mx_by_type_and_name(self):
        match = dns_manager.find_matching_record(self.existing, "MX", "example.com")
        self.assertIsNotNone(match)
        self.assertEqual(match["id"], "r2")

    def test_case_insensitive_type(self):
        match = dns_manager.find_matching_record(self.existing, "txt", "example.com")
        self.assertIsNotNone(match)
        self.assertEqual(match["id"], "r1")

    def test_no_match_wrong_name(self):
        result = dns_manager.find_matching_record(self.existing, "TXT", "other.example.com")
        self.assertIsNone(result)

    def test_no_match_wrong_type(self):
        result = dns_manager.find_matching_record(self.existing, "A", "example.com")
        self.assertIsNone(result)

    def test_empty_existing_list(self):
        result = dns_manager.find_matching_record([], "TXT", "example.com")
        self.assertIsNone(result)


# ===========================================================================
# records_differ
# ===========================================================================

class TestRecordsDiffer(unittest.TestCase):

    def _existing(self, content="v=spf1 -all", ttl=3600, proxied=False, priority=None):
        rec = {"content": content, "ttl": ttl, "proxied": proxied}
        if priority is not None:
            rec["priority"] = priority
        return rec

    def _desired(self, rtype="TXT", content="v=spf1 -all", ttl=3600, proxied=False, priority=None):
        rec = {"type": rtype, "content": content, "ttl": ttl, "proxied": proxied}
        if priority is not None:
            rec["priority"] = priority
        return rec

    # --- No difference cases ------------------------------------------------

    def test_identical_txt_record_no_diff(self):
        self.assertFalse(
            dns_manager.records_differ(
                self._existing(),
                self._desired(),
            )
        )

    def test_identical_mx_record_no_diff(self):
        existing = self._existing(content="mail.example.com", priority=10)
        desired = self._desired(rtype="MX", content="mail.example.com", priority=10)
        self.assertFalse(dns_manager.records_differ(existing, desired))

    # --- Content differs ----------------------------------------------------

    def test_content_changed_returns_true(self):
        existing = self._existing(content="old-value")
        desired = self._desired(content="new-value")
        self.assertTrue(dns_manager.records_differ(existing, desired))

    # --- TTL differs --------------------------------------------------------

    def test_ttl_changed_returns_true(self):
        existing = self._existing(ttl=3600)
        desired = self._desired(ttl=300)
        self.assertTrue(dns_manager.records_differ(existing, desired))

    def test_ttl_auto_sentinel_matches(self):
        """desired without explicit ttl defaults to 1; existing ttl=1 → no diff."""
        existing = self._existing(ttl=1)
        desired = {"type": "TXT", "content": "v=spf1 -all", "proxied": False}
        self.assertFalse(dns_manager.records_differ(existing, desired))

    # --- Proxied differs ----------------------------------------------------

    def test_proxied_changed_returns_true(self):
        existing = self._existing(proxied=False)
        desired = self._desired(proxied=True)
        self.assertTrue(dns_manager.records_differ(existing, desired))

    # --- Priority (MX) differs ----------------------------------------------

    def test_mx_priority_changed_returns_true(self):
        existing = self._existing(content="mail.example.com", priority=10)
        desired = self._desired(rtype="MX", content="mail.example.com", priority=20)
        self.assertTrue(dns_manager.records_differ(existing, desired))

    def test_non_mx_priority_ignored(self):
        """Priority field on a TXT record should not cause a diff."""
        existing = {"content": "v=spf1 -all", "ttl": 3600, "proxied": False, "priority": 999}
        desired = {"type": "TXT", "content": "v=spf1 -all", "ttl": 3600, "proxied": False}
        self.assertFalse(dns_manager.records_differ(existing, desired))


# ===========================================================================
# build_cf_payload
# ===========================================================================

class TestBuildCfPayload(unittest.TestCase):

    def test_txt_record_payload(self):
        record = {
            "type": "TXT",
            "name": "example.com",
            "content": "v=spf1 -all",
            "ttl": 3600,
            "proxied": False,
        }
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["type"], "TXT")
        self.assertEqual(payload["name"], "example.com")
        self.assertEqual(payload["content"], "v=spf1 -all")
        self.assertEqual(payload["ttl"], 3600)
        self.assertFalse(payload["proxied"])
        self.assertNotIn("priority", payload)

    def test_mx_record_payload_includes_priority(self):
        record = {
            "type": "MX",
            "name": "example.com",
            "content": "mail.example.com",
            "priority": 10,
            "ttl": 3600,
            "proxied": False,
        }
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["type"], "MX")
        self.assertEqual(payload["priority"], 10)

    def test_mx_record_default_priority(self):
        """MX without explicit priority gets default of 10."""
        record = {
            "type": "MX",
            "name": "example.com",
            "content": "mail.example.com",
        }
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["priority"], 10)

    def test_type_uppercased(self):
        record = {"type": "txt", "name": "example.com", "content": "v=spf1 -all"}
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["type"], "TXT")

    def test_defaults_when_optional_fields_absent(self):
        """ttl defaults to 1, proxied defaults to False when not specified."""
        record = {"type": "TXT", "name": "example.com", "content": "value"}
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["ttl"], 1)
        self.assertFalse(payload["proxied"])

    def test_cname_dkim_no_priority(self):
        record = {
            "type": "CNAME",
            "name": "mail._domainkey.example.com",
            "content": "mail._domainkey.provider.com",
            "ttl": 3600,
            "proxied": False,
        }
        payload = dns_manager.build_cf_payload(record)
        self.assertNotIn("priority", payload)

    def test_dmarc_txt_payload(self):
        record = {
            "type": "TXT",
            "name": "_dmarc.example.com",
            "content": "v=DMARC1; p=none; rua=mailto:reports@example.com; pct=100",
            "ttl": 3600,
            "proxied": False,
        }
        payload = dns_manager.build_cf_payload(record)
        self.assertEqual(payload["name"], "_dmarc.example.com")
        self.assertIn("DMARC1", payload["content"])


# ===========================================================================
# upsert_record — the core reconcile logic
# ===========================================================================

class TestUpsertRecord(unittest.TestCase):
    """
    Tests for upsert_record with cf_post / cf_put mocked out.
    We test: create-when-missing, update-when-changed, skip-when-identical.
    """

    ZONE = "zone-abc"
    TOKEN = "tok-xyz"

    def _desired_txt(self, content="v=spf1 -all", ttl=3600):
        return {
            "type": "TXT",
            "name": "example.com",
            "content": content,
            "ttl": ttl,
            "proxied": False,
        }

    def _desired_mx(self, content="mail.example.com", priority=10):
        return {
            "type": "MX",
            "name": "example.com",
            "content": content,
            "priority": priority,
            "ttl": 3600,
            "proxied": False,
        }

    # --- CREATE -------------------------------------------------------------

    @patch("dns_manager.cf_post")
    def test_create_when_no_existing_record(self, mock_post):
        mock_post.return_value = {"success": True, "result": {"id": "new-1"}}
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=self._desired_txt(),
            existing_records=[],
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "created")
        mock_post.assert_called_once()
        _, _, payload = mock_post.call_args[0]
        self.assertEqual(payload["type"], "TXT")
        self.assertEqual(payload["content"], "v=spf1 -all")

    @patch("dns_manager.cf_post")
    def test_create_mx_when_missing(self, mock_post):
        mock_post.return_value = {"success": True, "result": {"id": "new-2"}}
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=self._desired_mx(),
            existing_records=[],
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "created")
        _, _, payload = mock_post.call_args[0]
        self.assertEqual(payload["priority"], 10)

    @patch("dns_manager.cf_post")
    def test_dry_run_create_does_not_call_post(self, mock_post):
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=self._desired_txt(),
            existing_records=[],
            dry_run=True,
            verbose=False,
        )
        self.assertEqual(status, "created")
        mock_post.assert_not_called()

    # --- UPDATE -------------------------------------------------------------

    @patch("dns_manager.cf_put")
    def test_update_when_content_changed(self, mock_put):
        mock_put.return_value = {"success": True, "result": {"id": "rec-1"}}
        existing = [_cf_record("TXT", "example.com", "v=spf1 include:old.com -all", ttl=3600, record_id="rec-1")]
        desired = self._desired_txt(content="v=spf1 include:new.com -all")
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "updated")
        mock_put.assert_called_once()
        path_arg = mock_put.call_args[0][0]
        self.assertIn("rec-1", path_arg)

    @patch("dns_manager.cf_put")
    def test_update_when_ttl_changed(self, mock_put):
        mock_put.return_value = {"success": True, "result": {"id": "rec-2"}}
        existing = [_cf_record("TXT", "example.com", "v=spf1 -all", ttl=3600, record_id="rec-2")]
        desired = self._desired_txt(ttl=300)
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "updated")
        mock_put.assert_called_once()

    @patch("dns_manager.cf_put")
    def test_update_mx_priority_changed(self, mock_put):
        mock_put.return_value = {"success": True, "result": {"id": "rec-3"}}
        existing = [_cf_record("MX", "example.com", "mail.example.com", ttl=3600, priority=10, record_id="rec-3")]
        desired = self._desired_mx(priority=20)
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "updated")

    @patch("dns_manager.cf_put")
    def test_dry_run_update_does_not_call_put(self, mock_put):
        existing = [_cf_record("TXT", "example.com", "old-content", record_id="rec-9")]
        desired = self._desired_txt(content="new-content")
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=True,
            verbose=False,
        )
        self.assertEqual(status, "updated")
        mock_put.assert_not_called()

    # --- SKIP (idempotent) --------------------------------------------------

    @patch("dns_manager.cf_post")
    @patch("dns_manager.cf_put")
    def test_skip_when_record_identical(self, mock_put, mock_post):
        existing = [_cf_record("TXT", "example.com", "v=spf1 -all", ttl=3600, proxied=False, record_id="rec-5")]
        desired = self._desired_txt(content="v=spf1 -all", ttl=3600)
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "skipped")
        mock_post.assert_not_called()
        mock_put.assert_not_called()

    @patch("dns_manager.cf_post")
    @patch("dns_manager.cf_put")
    def test_skip_mx_when_identical(self, mock_put, mock_post):
        existing = [
            _cf_record("MX", "example.com", "mail.example.com", ttl=3600, proxied=False, priority=10, record_id="r6")
        ]
        desired = self._desired_mx(content="mail.example.com", priority=10)
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=False,
            verbose=False,
        )
        self.assertEqual(status, "skipped")
        mock_post.assert_not_called()
        mock_put.assert_not_called()

    @patch("dns_manager.cf_post")
    @patch("dns_manager.cf_put")
    def test_idempotent_dry_run_skip(self, mock_put, mock_post):
        """Dry-run on an already-correct record still returns 'skipped' without API calls."""
        existing = [_cf_record("TXT", "example.com", "v=spf1 -all", ttl=3600, record_id="r7")]
        desired = self._desired_txt(content="v=spf1 -all", ttl=3600)
        status = dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=True,
            verbose=False,
        )
        self.assertEqual(status, "skipped")
        mock_post.assert_not_called()
        mock_put.assert_not_called()


# ===========================================================================
# fetch_existing_records — pagination
# ===========================================================================

class TestFetchExistingRecords(unittest.TestCase):

    @patch("dns_manager.cf_get")
    def test_single_page(self, mock_get):
        records = [_cf_record("TXT", "example.com", "v=spf1 -all")]
        mock_get.return_value = _cf_response(records, total_pages=1)
        result = dns_manager.fetch_existing_records("zone-1", "tok")
        self.assertEqual(len(result), 1)
        mock_get.assert_called_once()

    @patch("dns_manager.cf_get")
    def test_multi_page_fetches_all(self, mock_get):
        page1 = [_cf_record("TXT", "example.com", f"value-{i}", record_id=f"r{i}") for i in range(3)]
        page2 = [_cf_record("MX", "example.com", "mail.example.com", record_id="mx1")]

        mock_get.side_effect = [
            {"success": True, "result": page1, "result_info": {"total_pages": 2}},
            {"success": True, "result": page2, "result_info": {"total_pages": 2}},
        ]
        result = dns_manager.fetch_existing_records("zone-2", "tok")
        self.assertEqual(len(result), 4)
        self.assertEqual(mock_get.call_count, 2)

    @patch("dns_manager.cf_get")
    def test_empty_zone(self, mock_get):
        mock_get.return_value = _cf_response([], total_pages=1)
        result = dns_manager.fetch_existing_records("zone-empty", "tok")
        self.assertEqual(result, [])


# ===========================================================================
# cf_get / cf_post / cf_put — HTTP layer
# ===========================================================================

class TestHttpHelpers(unittest.TestCase):
    """Verify the HTTP helpers handle success and error responses correctly."""

    def _mock_response(self, json_data, status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data
        resp.raise_for_status.return_value = None
        return resp

    def _mock_error_response(self, json_data, status_code=400):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data
        import requests as req
        http_err = req.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_err
        return resp

    @patch("dns_manager.requests.get")
    def test_cf_get_success(self, mock_get):
        mock_get.return_value = self._mock_response({"success": True, "result": [], "result_info": {"total_pages": 1}})
        data = dns_manager.cf_get("/zones/z/dns_records", "tok")
        self.assertTrue(data["success"])

    @patch("dns_manager.requests.get")
    def test_cf_get_api_failure_raises(self, mock_get):
        mock_get.return_value = self._mock_response(
            {"success": False, "errors": [{"code": 9109, "message": "Invalid zone identifier"}]}
        )
        with self.assertRaises(RuntimeError):
            dns_manager.cf_get("/zones/bad/dns_records", "tok")

    @patch("dns_manager.requests.post")
    def test_cf_post_success(self, mock_post):
        mock_post.return_value = self._mock_response({"success": True, "result": {"id": "new-id"}})
        data = dns_manager.cf_post("/zones/z/dns_records", "tok", {"type": "TXT"})
        self.assertEqual(data["result"]["id"], "new-id")

    @patch("dns_manager.requests.post")
    def test_cf_post_api_failure_raises(self, mock_post):
        mock_post.return_value = self._mock_response(
            {"success": False, "errors": [{"code": 1004, "message": "DNS Validation Error"}]}
        )
        with self.assertRaises(RuntimeError):
            dns_manager.cf_post("/zones/z/dns_records", "tok", {})

    @patch("dns_manager.requests.put")
    def test_cf_put_success(self, mock_put):
        mock_put.return_value = self._mock_response({"success": True, "result": {"id": "upd-id"}})
        data = dns_manager.cf_put("/zones/z/dns_records/upd-id", "tok", {"type": "TXT"})
        self.assertEqual(data["result"]["id"], "upd-id")

    @patch("dns_manager.requests.put")
    def test_cf_put_api_failure_raises(self, mock_put):
        mock_put.return_value = self._mock_response(
            {"success": False, "errors": [{"code": 81058, "message": "Record already exists"}]}
        )
        with self.assertRaises(RuntimeError):
            dns_manager.cf_put("/zones/z/dns_records/r1", "tok", {})


# ===========================================================================
# load_records_file
# ===========================================================================

class TestLoadRecordsFile(unittest.TestCase):
    """Test YAML loading and validation using a temp file."""

    def _write_yaml(self, tmp_path, content: str):
        tmp_path.write_text(content, encoding="utf-8")
        return str(tmp_path)

    def test_valid_file_returns_config(self, tmp_path=None):
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            fh.write(
                "zone_id: 'abc123'\n"
                "records:\n"
                "  - type: TXT\n"
                "    name: example.com\n"
                "    content: 'v=spf1 -all'\n"
            )
            path = fh.name
        try:
            config = dns_manager.load_records_file(path)
            self.assertEqual(config["zone_id"], "abc123")
            self.assertEqual(len(config["records"]), 1)
        finally:
            os.unlink(path)

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            dns_manager.load_records_file("/nonexistent/path/records.yaml")

    def test_missing_zone_id_exits(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            fh.write("records:\n  - type: TXT\n    name: x\n    content: y\n")
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                dns_manager.load_records_file(path)
        finally:
            os.unlink(path)

    def test_missing_records_key_exits(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            fh.write("zone_id: 'abc'\n")
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                dns_manager.load_records_file(path)
        finally:
            os.unlink(path)

    def test_record_missing_required_key_exits(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            fh.write(
                "zone_id: 'abc'\n"
                "records:\n"
                "  - type: TXT\n"
                "    name: example.com\n"
                # missing 'content'
            )
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                dns_manager.load_records_file(path)
        finally:
            os.unlink(path)

    def test_multiple_records_loaded(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            fh.write(
                "zone_id: 'z1'\n"
                "records:\n"
                "  - type: TXT\n"
                "    name: example.com\n"
                "    content: 'v=spf1 -all'\n"
                "  - type: MX\n"
                "    name: example.com\n"
                "    content: 'mail.example.com'\n"
                "    priority: 10\n"
                "  - type: CNAME\n"
                "    name: 'mail._domainkey.example.com'\n"
                "    content: 'mail._domainkey.provider.com'\n"
                "  - type: TXT\n"
                "    name: '_dmarc.example.com'\n"
                "    content: 'v=DMARC1; p=none; rua=mailto:r@example.com'\n"
            )
            path = fh.name
        try:
            config = dns_manager.load_records_file(path)
            self.assertEqual(len(config["records"]), 4)
            types = [r["type"] for r in config["records"]]
            self.assertIn("TXT", types)
            self.assertIn("MX", types)
            self.assertIn("CNAME", types)
        finally:
            os.unlink(path)


# ===========================================================================
# Integration-style: full reconcile across multiple record types
# ===========================================================================

class TestReconcileIntegration(unittest.TestCase):
    """
    Drive upsert_record for a realistic set of email DNS records.
    Verifies create/update/skip decisions without real HTTP calls.
    """

    ZONE = "zone-int"
    TOKEN = "tok-int"

    def _upsert(self, desired, existing, dry_run=False):
        return dns_manager.upsert_record(
            zone_id=self.ZONE,
            token=self.TOKEN,
            desired=desired,
            existing_records=existing,
            dry_run=dry_run,
            verbose=False,
        )

    @patch("dns_manager.cf_post")
    def test_spf_created_on_fresh_zone(self, mock_post):
        mock_post.return_value = {"success": True, "result": {"id": "spf-1"}}
        status = self._upsert(
            desired={"type": "TXT", "name": "example.com", "content": "v=spf1 include:mail.example.com -all", "ttl": 3600, "proxied": False},
            existing=[],
        )
        self.assertEqual(status, "created")

    @patch("dns_manager.cf_post")
    def test_dkim_cname_created_on_fresh_zone(self, mock_post):
        mock_post.return_value = {"success": True, "result": {"id": "dkim-1"}}
        status = self._upsert(
            desired={"type": "CNAME", "name": "mail._domainkey.example.com", "content": "mail._domainkey.provider.com", "ttl": 3600, "proxied": False},
            existing=[],
        )
        self.assertEqual(status, "created")

    @patch("dns_manager.cf_post")
    def test_dmarc_txt_created_on_fresh_zone(self, mock_post):
        mock_post.return_value = {"success": True, "result": {"id": "dmarc-1"}}
        status = self._upsert(
            desired={"type": "TXT", "name": "_dmarc.example.com", "content": "v=DMARC1; p=none; rua=mailto:r@example.com; pct=100", "ttl": 3600, "proxied": False},
            existing=[],
        )
        self.assertEqual(status, "created")

    @patch("dns_manager.cf_post")
    @patch("dns_manager.cf_put")
    def test_all_records_idempotent(self, mock_put, mock_post):
        """Run all four email DNS record types; all already match → all skip."""
        records_in = [
            _cf_record("TXT", "example.com", "v=spf1 include:mail.example.com -all", ttl=3600, record_id="r1"),
            _cf_record("MX", "example.com", "mail.example.com", ttl=3600, priority=10, record_id="r2"),
            _cf_record("CNAME", "mail._domainkey.example.com", "mail._domainkey.provider.com", ttl=3600, record_id="r3"),
            _cf_record("TXT", "_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@example.com; pct=100", ttl=3600, record_id="r4"),
        ]
        desired_list = [
            {"type": "TXT", "name": "example.com", "content": "v=spf1 include:mail.example.com -all", "ttl": 3600, "proxied": False},
            {"type": "MX", "name": "example.com", "content": "mail.example.com", "priority": 10, "ttl": 3600, "proxied": False},
            {"type": "CNAME", "name": "mail._domainkey.example.com", "content": "mail._domainkey.provider.com", "ttl": 3600, "proxied": False},
            {"type": "TXT", "name": "_dmarc.example.com", "content": "v=DMARC1; p=none; rua=mailto:r@example.com; pct=100", "ttl": 3600, "proxied": False},
        ]
        for desired, existing_r in zip(desired_list, records_in):
            # Each desired record has its match in existing
            status = self._upsert(desired=desired, existing=records_in)
            self.assertEqual(status, "skipped", f"Expected skip for {desired['type']} {desired['name']}")
        mock_post.assert_not_called()
        mock_put.assert_not_called()

    @patch("dns_manager.cf_put")
    def test_spf_policy_update(self, mock_put):
        """SPF content change: -all → ~all."""
        mock_put.return_value = {"success": True, "result": {"id": "spf-r"}}
        existing = [_cf_record("TXT", "example.com", "v=spf1 include:mail.example.com -all", ttl=3600, record_id="spf-r")]
        status = self._upsert(
            desired={"type": "TXT", "name": "example.com", "content": "v=spf1 include:mail.example.com ~all", "ttl": 3600, "proxied": False},
            existing=existing,
        )
        self.assertEqual(status, "updated")
        mock_put.assert_called_once()

    @patch("dns_manager.cf_put")
    def test_dmarc_policy_escalation(self, mock_put):
        """DMARC p=none → p=quarantine triggers an update."""
        mock_put.return_value = {"success": True, "result": {"id": "dmarc-r"}}
        existing = [_cf_record("TXT", "_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@example.com; pct=100", ttl=3600, record_id="dmarc-r")]
        status = self._upsert(
            desired={"type": "TXT", "name": "_dmarc.example.com", "content": "v=DMARC1; p=quarantine; rua=mailto:r@example.com; pct=100", "ttl": 3600, "proxied": False},
            existing=existing,
        )
        self.assertEqual(status, "updated")


if __name__ == "__main__":
    unittest.main()
