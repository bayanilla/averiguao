"""HTTP server probes: Host/Origin/Sec-Fetch handling, CSRF, route confusion, SQL-ish parameters, body handling,
error leakage, connection timeouts and bind address. Uses a completed hostile-data run; no network."""

from __future__ import annotations

import json
import socket
import time
import unittest

from tests.security._hostile import HostileRun, raw_request, start_server


class ServerProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store, cls.run_id = HostileRun.get()
        cls.httpd = start_server(cls.store)
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, headers=None, body=None, host="default"):
        return raw_request(self.port, method, path, headers, body, host=host)

    # ------------------------------------------------------------ binding
    def test_binds_loopback_only(self):
        """Guard: the server never listens beyond 127.0.0.1."""
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    # ------------------------------------------------------------ Host / Origin / Sec-Fetch
    def test_host_header_variants_rejected(self):
        """Guard: DNS-rebinding style Host values (missing, no port, wrong port, trailing dot, IPv6, short
        IPv4 forms, 0.0.0.0, upper case, attacker names, userinfo) are refused with 403."""
        p = self.port
        hosts = [None, "", "127.0.0.1", f"127.0.0.1.:{p}", f"localhost.:{p}", f"[::1]:{p}", f"127.1:{p}",
                 f"0.0.0.0:{p}", f"2130706433:{p}", f"LOCALHOST:{p}", f"evil.test:{p}", f"127.0.0.1:{p}.evil.test",
                 f"user@127.0.0.1:{p}", f"127.0.0.1:{p} , evil.test", f"127.0.0.1:0{p}", f"127.0.0.1:{p + 1}"]
        for host in hosts:
            for path in ("/api/runs", f"/api/runs/{self.run_id}/export.json", "/"):
                response, _ = self.req("GET", path, host=host)
                self.assertEqual(response.status, 403, f"Host {host!r} {path}")

    def test_cross_origin_and_cross_site_requests_rejected(self):
        """Guard: foreign Origin (including 'null', other loopback ports, https, trailing slash) and
        Sec-Fetch-Site cross-site/same-site are refused for reads, exports and writes."""
        p = self.port
        bad = [{"Origin": "null"}, {"Origin": f"http://127.0.0.1:{p + 1}"}, {"Origin": f"https://127.0.0.1:{p}"},
               {"Origin": f"http://127.0.0.1:{p}/"}, {"Origin": "http://evil.test"},
               {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"},
               {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}]
        for headers in bad:
            for path in (f"/api/runs/{self.run_id}/export.csv", f"/api/runs/{self.run_id}/export.md",
                         f"/api/runs/{self.run_id}/findings", "/api/inventory"):
                response, body = self.req("GET", path, headers)
                self.assertEqual(response.status, 403, (headers, path))
                self.assertNotIn(b"onerror", body)

    def test_csrf_writes_rejected(self):
        """Guard: a cross-site form/fetch POST (text/plain, form-urlencoded, or JSON with a foreign Origin)
        never creates a snapshot or a run."""
        before = len(self.store.snapshots()), len(self.store.runs())
        payload = json.dumps({"csv": "203.0.113.0/24,evil"}).encode()
        for headers in ({"Content-Type": "text/plain", "Origin": "http://evil.test"},
                        {"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://evil.test"},
                        {"Content-Type": "application/json", "Origin": "http://evil.test"},
                        {"Content-Type": "text/plain"},
                        {"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}):
            for path in ("/api/inventory", "/api/runs"):
                response, _ = self.req("POST", path, headers, payload)
                self.assertIn(response.status, (403, 415), (headers, path))
        self.assertEqual((len(self.store.snapshots()), len(self.store.runs())), before)

    def test_absolute_form_request_target_still_checks_host(self):
        """Guard: an absolute-form request line naming another host does not bypass the Host check."""
        response, _ = self.req("GET", f"http://evil.test/api/runs", host=f"evil.test:{self.port}")
        self.assertEqual(response.status, 403)

    # ------------------------------------------------------------ routes
    def test_route_confusion_and_traversal(self):
        """Guard: encoded slashes, dot segments, double slashes and path-parameter tricks never reach files
        outside the static map or another run's data."""
        for path in ("/%2e%2e/averiguao.py", "/..%2faverigua o.py".replace(" ", ""), "/static/../averiguao.py",
                     "//etc/passwd", "/app.js/..", "/api%2fhealth", "/api/runs/%2e%2e", f"/api/runs/{self.run_id}%2f..",
                     f"/api/runs/{self.run_id.upper()}", f"/api/runs/{self.run_id}/export.json%00.html",
                     f"/api/runs/{self.run_id}/findings/fd:ip:..%2f..%2f", "/index.html;.js", "/web/index.html",
                     "/api/runs/" + "a" * 5000):
            response, body = self.req("GET", path)
            self.assertIn(response.status, (400, 404), path)
            self.assertNotIn(b"import", body)

    def test_query_parameters_are_not_sql(self):
        """Guard: sort/queue/type/flag are allow-listed and q is a literal substring ('%' and '_' are not
        wildcards), so SQL fragments are rejected or match nothing."""
        base = f"/api/runs/{self.run_id}/findings"
        for qs in ("sort=rank;DROP%20TABLE%20findings", "sort=value%20DESC", "queue=new'%20OR%201=1--",
                   "type=ip%22", "flag=conflict|", "flag=" + "a" * 41):
            response, _ = self.req("GET", f"{base}?{qs}")
            self.assertEqual(response.status, 400, qs)
        for q in ("%", "_", "%25", "'%20OR%20'1'='1"):
            response, body = self.req("GET", f"{base}?q={q}")
            self.assertEqual(response.status, 200, q)
            self.assertEqual(json.loads(body)["total"], 0, q)
        response, body = self.req("GET", f"{base}?limit=999999999&offset=999999999")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(body)["findings"], [])

    def test_errors_do_not_leak_internals(self):
        """Guard: malformed requests produce short JSON errors with no traceback or filesystem path."""
        qs = "&".join(f"k{i}=1" for i in range(40))
        for method, path, headers, body in (
                ("GET", f"/api/runs/{self.run_id}/findings?{qs}", None, None),
                ("GET", "/%ff%fe", None, None),
                ("POST", "/api/preview", {"Content-Type": "application/json"}, b'{"config": {"seeds": 5}}'),
                ("POST", "/api/inventory", {"Content-Type": "application/json"}, b'{"csv": "\\u0000,,,,"}')):
            response, payload = self.req(method, path, headers, body)
            self.assertGreaterEqual(response.status, 400, path)
            self.assertNotIn(b"Traceback", payload)
            self.assertNotIn(b"/home/", payload)
            self.assertNotIn(b".py", payload)

    # ------------------------------------------------------------ body handling
    def test_content_length_variants(self):
        """Guard: negative, non-numeric, oversized and chunked bodies are refused before reading."""
        for headers in ({"Content-Length": "-1"}, {"Content-Length": "abc"},
                        {"Content-Length": str(10 ** 12)}, {"Transfer-Encoding": "chunked"}):
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            lines = [f"POST /api/inventory HTTP/1.1", f"Host: 127.0.0.1:{self.port}",
                     "Content-Type: application/json", *(f"{k}: {v}" for k, v in headers.items()), "", ""]
            conn.sendall("\r\n".join(lines).encode())
            data = conn.recv(200)
            conn.close()
            self.assertRegex(data, rb"^HTTP/1\.\d 4\d\d", headers)

    def test_stalled_connections_time_out(self):
        """ISSUE (slowloris / stalled body): Handler sets no socket timeout (BaseHTTPRequestHandler.timeout is
        None) and ThreadingHTTPServer spawns an unbounded thread per connection. A client that sends a partial
        request line, or a Content-Length larger than the body it sends, pins a thread blocked in readline()/
        rfile.read() forever; any local process can exhaust threads/file descriptors and hang the UI.
        EXPECTED: a finite per-connection timeout (e.g. Handler.timeout = 10-30 s) so a stalled client is
        dropped, ideally with a cap on concurrent connections."""
        timeout = self.httpd.RequestHandlerClass.timeout
        self.assertIsNotNone(timeout, "Handler.timeout is None: stalled connections are held forever")
        self.assertLessEqual(timeout, 60)
        conn = socket.create_connection(("127.0.0.1", self.port), timeout=timeout + 5)
        conn.sendall(f"POST /api/inventory HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                     f"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{{".encode())
        start = time.monotonic()
        try:
            conn.recv(1)
        except socket.timeout:
            self.fail("server kept a stalled request open past its own timeout")
        finally:
            conn.close()
        self.assertLess(time.monotonic() - start, timeout + 5)

    # ------------------------------------------------------------ exports
    def test_exports_are_attachments_with_safe_headers(self):
        """Guard: exports are same-origin only, served as attachments with nosniff and a fixed filename."""
        for ext, mime in (("json", "application/json"), ("csv", "text/csv"), ("md", "text/markdown")):
            response, body = self.req("GET", f"/api/runs/{self.run_id}/export.{ext}")
            self.assertEqual(response.status, 200)
            self.assertTrue(response.getheader("Content-Type").startswith(mime))
            self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
            self.assertRegex(response.getheader("Content-Disposition"),
                             rf'^attachment; filename="averiguao-[0-9a-f]{{8}}\.{ext}"$')
            self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))


if __name__ == "__main__":
    unittest.main()
