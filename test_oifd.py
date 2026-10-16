import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import oifd


class InputTests(unittest.TestCase):
    def test_large_public_ranges_are_accepted_without_expansion(self):
        self.assertEqual(oifd.parse_public_network("8.8.8.8/16"), ipaddress.IPv4Network("8.8.0.0/16"))
        self.assertEqual(oifd.parse_public_network("8.8.8.8/8").num_addresses, 16_777_216)

    def test_private_and_ipv6_are_rejected(self):
        for value in ("10.0.0.0/8", "192.168.1.1", "2001:4860::/32", "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                oifd.parse_public_network(value)

    def test_inventory_parses_header_and_normalizes(self):
        result = oifd.parse_inventory("IP_or_CIDR,label\n8.8.8.8,Known DNS\n8.8.8.0/24,Range\n")
        self.assertEqual(result[0][0], "8.8.8.8/32")
        self.assertEqual(result[1][0], "8.8.8.0/24")

    def test_inventory_uses_most_specific_match(self):
        entries = [{"cidr": "8.0.0.0/8", "label": "Broad"},
                   {"cidr": "8.8.8.0/24", "label": "Specific"}]
        matcher = oifd.InventoryMatcher(entries)
        self.assertEqual(matcher.match(int(ipaddress.IPv4Address("8.8.8.8")))["label"], "Specific")
        self.assertEqual(matcher.match(int(ipaddress.IPv4Address("8.9.0.1")))["label"], "Broad")


class StoreAndRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "test.db"
        self.store = oifd.Store(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_batch_reconciliation_and_restart_resume(self):
        self.store.replace_inventory(oifd.parse_inventory("8.8.8.0/31,Approved pair"))
        job = self.store.create_job(oifd.parse_public_network("8.8.8.0/30"))
        calls = []

        def fake(ip):
            calls.append(ip)
            if ip.endswith(".3"):
                return "empty", None
            return "found", {"ports": [443], "hostnames": [], "cpes": [], "tags": [], "vulns": []}

        runner = oifd.Runner(self.store, rate=1000, workers=2, batch_size=2, fetcher=fake)
        self.assertTrue(runner.start(job["id"]))
        runner.thread.join(timeout=3)
        finished = self.store.job(job["id"])
        self.assertEqual(finished["status"], "complete")
        self.assertEqual((finished["found"], finished["empty"], finished["next_offset"]), (3, 1, 4))
        self.assertEqual(len(calls), 4)
        rows = self.store.results(job["id"])
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["inventory_status"], "known")
        self.assertEqual(rows[2]["inventory_status"], "unaccounted")
        self.assertIsNone(rows[0]["source_observed_at"])
        self.assertFalse(runner.start(job["id"]))

        another = self.store.create_job(oifd.parse_public_network("8.8.4.4"))
        self.store.status(another["id"], "running")
        reopened = oifd.Store(self.path)
        self.assertEqual(reopened.job(another["id"])["status"], "paused")

    def test_rate_limit_retries_without_losing_result(self):
        attempts = 0

        def throttled(ip):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise oifd.RateLimited(0)
            return "empty", None

        job = self.store.create_job(oifd.parse_public_network("8.8.4.4"))
        runner = oifd.Runner(self.store, rate=1000, workers=1, batch_size=1, fetcher=throttled)
        self.assertTrue(runner.start(job["id"]))
        runner.thread.join(timeout=3)
        self.assertEqual(attempts, 2)
        self.assertEqual(self.store.job(job["id"])["status"], "complete")

    def test_source_errors_pause_and_preserve_cursor(self):
        job = self.store.create_job(oifd.parse_public_network("8.8.8.0/29"))

        def failing(ip):
            return "error", {"message": "source unavailable"}

        runner = oifd.Runner(self.store, rate=1000, workers=2, batch_size=8, fetcher=failing)
        self.assertTrue(runner.start(job["id"]))
        runner.thread.join(timeout=3)
        result = self.store.job(job["id"])
        self.assertEqual(result["status"], "paused")
        self.assertEqual(result["next_offset"], 0)
        self.assertIn("source errors", result["last_error"])


class SourceTests(unittest.TestCase):
    def test_internetdb_found_and_404(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, count=-1):
                return json.dumps({"ip": "8.8.8.8", "ports": [53], "hostnames": []}).encode()

        with patch.object(oifd, "urlopen", return_value=Response()):
            status, data = oifd.fetch_internetdb("8.8.8.8")
        self.assertEqual(status, "found")
        self.assertEqual(data["ports"], [53])

        from urllib.error import HTTPError
        with patch.object(oifd, "urlopen", side_effect=HTTPError("url", 404, "Not found", {}, None)):
            self.assertEqual(oifd.fetch_internetdb("8.8.8.8"), ("empty", None))


if __name__ == "__main__":
    unittest.main()
