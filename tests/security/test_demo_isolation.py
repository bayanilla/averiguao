"""Demo mode safety: the synthetic world never touches live sources or the real database, and the live server
does not accept the documentation ranges the demo needs."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from averiguao_core import cli
from averiguao_core.connectors.fake import DEMO_CONFIG, FakeConnector
from tests.security._hostile import HostileRun, raw_request, start_server


class DemoIsolation(unittest.TestCase):
    def test_demo_uses_only_fake_connectors_and_separate_db(self):
        """Guard: --demo wires FakeConnector for every source and stores data in demo.sqlite3."""
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(data_dir=Path(tmp), rate=[], demo=True)
            store, factory, config = cli._setup(args)
            connectors = factory()
            self.assertEqual(set(connectors), {"ct", "dns", "rdap", "internetdb"})
            self.assertTrue(all(isinstance(c, FakeConnector) for c in connectors.values()))
            self.assertEqual(Path(store.path).name, "demo.sqlite3")
            self.assertEqual(config["seeds"], DEMO_CONFIG["seeds"])

    def test_live_server_rejects_documentation_ranges(self):
        """Guard: without --demo, the demo seeds (documentation ranges) are refused, and /api/health exposes
        no demo config."""
        store, _ = HostileRun.get()
        httpd = start_server(store, demo=False)
        try:
            port = httpd.server_address[1]
            body = json.dumps({"config": {**DEMO_CONFIG, "seeds": "198.51.100.0/28"}}).encode()
            response, _ = raw_request(port, "POST", "/api/preview", {"Content-Type": "application/json"}, body)
            self.assertEqual(response.status, 400)
            response, payload = raw_request(port, "GET", "/api/health")
            self.assertNotIn("demo_config", json.loads(payload))
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
