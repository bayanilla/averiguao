"""HTTP API (averiguao_core/server.py): origin checks, body limits, every route, 409s and path validation."""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from urllib.parse import quote

from averiguao_core import server as server_mod
from averiguao_core.connectors.fake import DEMO_CONFIG, DEMO_INVENTORY_CSV, demo_world
from averiguao_core.contracts import VERSION
from tests.fixtures.pipeline import run_pipeline


class FakeRunner:
    """Records calls; state machine just strict enough for the 409 paths."""

    def __init__(self, store):
        self.store = store
        self.submitted: list[str] = []
        self.reassess_error: Exception | None = None

    def submit(self, run_id):
        self.submitted.append(run_id)

    def pause(self, run_id):
        status = self.store.run(run_id)["status"]
        if status not in {"queued", "running"}:
            raise ValueError(f"Cannot pause a {status} run.")
        return "pausing"

    def resume(self, run_id):
        status = self.store.run(run_id)["status"]
        if status not in {"paused", "pausing"}:
            raise ValueError(f"Cannot resume a {status} run.")
        return "queued"

    def reassess(self, run_id):
        if self.reassess_error:
            raise self.reassess_error
        if self.store.run(run_id)["status"] != "complete":
            raise ValueError("Only a complete run can be reassessed.")


class ServerTest(unittest.TestCase):
    demo = True

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store, cls.run_id = run_pipeline(demo_world(), DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=cls.tmp.name)
        cls.runner = FakeRunner(cls.store)
        cls.httpd = server_mod.make_server(cls.store, cls.runner, port=0, demo=cls.demo, demo_config=dict(DEMO_CONFIG))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    # ------------------------------------------------------------ helpers
    def request(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if data is not None:
            hdrs["Content-Length"] = str(len(data))
        hdrs.update(headers or {})
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in hdrs.items():
            conn.putheader(key, value)
        conn.endheaders(data)
        response = conn.getresponse()
        payload = response.read()
        conn.close()
        return response, payload

    def json(self, method, path, body=None, headers=None, status=200):
        response, payload = self.request(method, path, body, headers)
        self.assertEqual(response.status, status, payload)
        self.assertTrue(response.getheader("Content-Type").startswith("application/json"))
        return json.loads(payload)

    # ------------------------------------------------------------ security
    def test_host_and_origin_checks(self):
        for headers in ({"Host": "evil.test"}, {"Host": f"evil.test:{self.port}"}, {"Host": "127.0.0.1:1"},
                        {"Origin": "http://evil.test"}, {"Origin": f"http://127.0.0.1:{self.port}.evil.test"},
                        {"Sec-Fetch-Site": "cross-site"}):
            self.json("GET", "/api/health", headers=headers, status=403)
            self.json("POST", "/api/inventory", {"csv": "1.2.3.4"}, headers=headers, status=403)
        self.json("GET", "/api/health", headers={"Host": f"localhost:{self.port}",
                                                  "Origin": f"http://localhost:{self.port}"})

    def test_security_headers_on_static_and_api(self):
        for path in ("/", "/app.js", "/style.css", "/themes.css", "/mucaro-mark.svg", "/api/health"):
            response, _ = self.request("GET", path)
            self.assertEqual(response.status, 200, path)
            self.assertIn("script-src 'self'", response.getheader("Content-Security-Policy"))
            self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.json("GET", "/../averiguao.py", status=404)
        self.json("GET", "/web/app.js", status=404)

    def test_body_limits_and_types(self):
        response, _ = self.request("POST", "/api/preview", raw=b"{}", headers={"Content-Type": "text/plain"})
        self.assertEqual(response.status, 415)
        response, _ = self.request("POST", "/api/preview", raw=b"x" * 10,
                                   headers={"Content-Type": "application/json",
                                            "Content-Length": str(server_mod.MAX_BODY + 1)})
        self.assertEqual(response.status, 413)
        response, _ = self.request("POST", "/api/preview", raw=b"[1]", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)
        response, _ = self.request("POST", "/api/preview", raw=b"{nope", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)
        response, _ = self.request("POST", "/api/preview", raw=b"", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)
        self.json("PUT", "/api/runs", status=405)

    # ------------------------------------------------------------ routes
    def test_health(self):
        data = self.json("GET", "/api/health")
        self.assertEqual(data["version"], VERSION)
        self.assertIs(data["demo"], True)
        self.assertEqual(data["demo_config"]["approval_ref"], DEMO_CONFIG["approval_ref"])

    def test_runs_list_and_get(self):
        runs = self.json("GET", "/api/runs")["runs"]
        self.assertIn(self.run_id, [r["id"] for r in runs])
        run = self.json("GET", f"/api/runs/{self.run_id}")
        self.assertEqual(run["status"], "complete")
        self.json("GET", f"/api/runs/{'0' * 32}", status=404)
        self.json("GET", "/api/runs/not-hex", status=404)
        self.json("GET", f"/api/runs/{self.run_id.upper()}", status=404)
        self.json("GET", f"/api/runs/{self.run_id}/nothing", status=404)

    def test_preview(self):
        data = self.json("POST", "/api/preview", {"config": DEMO_CONFIG})
        self.assertEqual([s["type"] for s in data["seeds"]], ["domain", "prefix"])
        self.assertEqual(data["estimated_queries"], (2 + server_mod.ROUGH_DOMAIN_EXPANSION * 3) + 17)
        self.assertIsInstance(data["warnings"], list)
        no_org = self.json("POST", "/api/preview", {"config": {**DEMO_CONFIG, "org_names": []}})
        self.assertTrue(any("organization" in w.lower() for w in no_org["warnings"]))
        ip = self.json("POST", "/api/preview", {"config": {**DEMO_CONFIG, "seeds": "198.51.100.7"}})
        self.assertEqual(ip["estimated_queries"], 2)
        err = self.json("POST", "/api/preview", {"config": {**DEMO_CONFIG, "approval_ref": ""}}, status=400)
        self.assertTrue(err["error"])
        self.json("POST", "/api/preview", {"config": {**DEMO_CONFIG, "seeds": "10.0.0.0/8"}}, status=400)
        self.json("POST", "/api/preview", {"config": "nope"}, status=400)

    def test_create_run(self):
        before = len(self.runner.submitted)
        run = self.json("POST", "/api/runs", {"config": DEMO_CONFIG}, status=201)
        self.assertEqual(run["status"], "queued")
        self.assertEqual(self.runner.submitted[before:], [run["id"]])
        self.json("POST", "/api/runs", {"config": {**DEMO_CONFIG, "seeds": ""}}, status=400)
        # queued run: pause allowed, resume and reassess conflict
        self.assertEqual(self.json("POST", f"/api/runs/{run['id']}/pause", {})["status"], "pausing")
        err = self.json("POST", f"/api/runs/{run['id']}/resume", {}, status=409)
        self.assertIn("resume", err["error"])
        self.json("POST", f"/api/runs/{run['id']}/reassess", {}, status=409)

    def test_actions_on_complete_run(self):
        self.json("POST", f"/api/runs/{self.run_id}/pause", {}, status=409)
        self.json("POST", f"/api/runs/{self.run_id}/resume", {}, status=409)
        self.assertEqual(self.json("POST", f"/api/runs/{self.run_id}/reassess", {})["status"], "complete")
        self.runner.reassess_error = RuntimeError("snapshot vanished")
        try:
            err = self.json("POST", f"/api/runs/{self.run_id}/reassess", {}, status=500)
            self.assertEqual(err["error"], "Reassessment failed.")  # no internal detail echoed
        finally:
            self.runner.reassess_error = None
        self.json("POST", f"/api/runs/{self.run_id}/explode", {}, status=404)
        self.json("POST", f"/api/runs/{'a' * 32}/pause", {}, status=404)

    def test_findings_filters(self):
        base = f"/api/runs/{self.run_id}/findings"
        everything = self.json("GET", base + "?limit=200")
        self.assertEqual(everything["total"], len(everything["findings"]))
        ranks = [f["rank"] for f in everything["findings"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))
        self.assertEqual(set(everything["findings"][0]["assessments"]),
                         {"ownership", "operational_control", "hosting", "service_association"})
        new = self.json("GET", base + "?queue=new")
        self.assertTrue(new["findings"])
        self.assertTrue(all(f["queue"] == "new" for f in new["findings"]))
        ips = self.json("GET", base + "?type=ip")
        self.assertTrue(all(f["asset_type"] == "ip" for f in ips["findings"]))
        q = self.json("GET", base + "?q=staging")
        self.assertEqual([f["value"] for f in q["findings"]], ["staging.example.com"])
        flagged = self.json("GET", base + "?flag=conflict")
        self.assertTrue(all("conflict" in f["flags"] for f in flagged["findings"]))
        page = self.json("GET", base + "?offset=2&limit=3&sort=value")
        self.assertEqual(len(page["findings"]), 3)
        self.assertEqual(page["total"], everything["total"])
        for bad in ("queue=bogus", "type=asn", "sort=evil", "offset=-1", "limit=abc", "flag=DROP%20TABLE"):
            self.json("GET", f"{base}?{bad}", status=400)

    def test_finding_detail(self):
        fid = "fd:hostname:staging.example.com"
        for path_id in (fid, quote(fid, safe="")):
            data = self.json("GET", f"/api/runs/{self.run_id}/findings/{path_id}")
            self.assertEqual(data["finding"]["id"], fid)
            self.assertEqual([a["dimension"] for a in data["assertions"]],
                             ["ownership", "operational_control", "hosting", "service_association"])
            self.assertEqual(data["path"][0]["subject"]["type"], "seed")
            self.assertEqual(data["path"][-1]["object"]["id"], "hostname:staging.example.com")
            self.assertTrue(all(hop["evidence"] for hop in data["path"]))
            self.assertTrue(data["evidence"])
        ip = self.json("GET", f"/api/runs/{self.run_id}/findings/fd:ip:198.51.100.9")
        self.assertEqual(ip["finding"]["value"], "198.51.100.9")
        self.json("GET", f"/api/runs/{self.run_id}/findings/fd:hostname:nope.example.com", status=404)
        self.json("GET", f"/api/runs/{self.run_id}/findings/{quote('<script>', safe='')}", status=404)
        self.json("GET", f"/api/runs/{self.run_id}/findings/%ff%fe", status=400)

    def test_coverage(self):
        data = self.json("GET", f"/api/runs/{self.run_id}/coverage?limit=5")
        self.assertEqual(len(data["coverage"]), 5)
        self.assertGreaterEqual(data["total"], 16)
        rest = self.json("GET", f"/api/runs/{self.run_id}/coverage?offset=5&limit=200")
        self.assertEqual(len(rest["coverage"]), data["total"] - 5)

    def test_exports(self):
        for ext, mime in (("json", "application/json"), ("csv", "text/csv"), ("md", "text/markdown")):
            response, payload = self.request("GET", f"/api/runs/{self.run_id}/export.{ext}")
            self.assertEqual(response.status, 200)
            self.assertTrue(response.getheader("Content-Type").startswith(mime))
            self.assertIn(f"averiguao-{self.run_id[:8]}.{ext}", response.getheader("Content-Disposition"))
            self.assertIsNone(response.getheader("Content-Length"))
            self.assertIn(b"fd:", payload)
        json.loads(self.request("GET", f"/api/runs/{self.run_id}/export.json")[1])
        self.json("GET", f"/api/runs/{'0' * 32}/export.csv", status=404)

    def test_inventory(self):
        data = self.json("GET", "/api/inventory")
        self.assertEqual(len(data["current"]["entries"]), 3)
        saved = self.json("POST", "/api/inventory", {"csv": "203.0.113.0/24,cdn\n*.example.com,all",
                                                     "label": "second", "as_of": "2026-09-01T00:00:00+00:00"})
        self.assertEqual(saved["entry_count"], 2)
        self.assertNotIn("entries", saved["snapshot"])
        data = self.json("GET", "/api/inventory")
        self.assertEqual(data["current"]["label"], "second")
        self.assertTrue(any(s["current"] for s in data["snapshots"]))
        self.json("POST", "/api/inventory", {"csv": "not an address,x"}, status=400)
        self.json("POST", "/api/inventory", {"csv": 5}, status=400)
        # restore the demo inventory for other tests
        self.json("POST", "/api/inventory", {"csv": DEMO_INVENTORY_CSV, "label": "Demo inventory"})

    def test_unknown_routes(self):
        self.json("GET", "/api/nothing", status=404)
        self.json("POST", "/api/nothing", {}, status=404)
        self.json("GET", "/api", status=404)


class NonDemoServerTest(ServerTest):
    """Outside demo mode documentation ranges are refused."""
    demo = False

    def test_health(self):
        data = self.json("GET", "/api/health")
        self.assertIs(data["demo"], False)
        self.assertNotIn("demo_config", data)

    def test_preview(self):
        err = self.json("POST", "/api/preview", {"config": DEMO_CONFIG}, status=400)
        self.assertTrue(err["error"])

    def test_create_run(self):
        self.json("POST", "/api/runs", {"config": DEMO_CONFIG}, status=400)


if __name__ == "__main__":
    unittest.main()
