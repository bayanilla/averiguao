"""Connector and HTTP client tests. No sockets: an injected transport serves canned responses."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import threading
import unittest
from email.utils import formatdate
from pathlib import Path

from averiguao_core.connectors.ct import CTConnector
from averiguao_core.connectors.dns import DNSConnector
from averiguao_core.connectors.http import HttpClient, RateGate, SourceError, parse_retry_after
from averiguao_core.connectors.internetdb import InternetDBConnector
from averiguao_core.connectors.rdap import RDAPConnector
from averiguao_core.contracts import USER_AGENT

FIXTURES = Path(__file__).parent / "fixtures" / "http"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self._headers = headers
        self._body = body
        self._pos = 0

    def getheaders(self):
        return list(self._headers.items())

    def read(self, amt=None):
        end = len(self._body) if amt is None else self._pos + amt
        chunk = self._body[self._pos:end]
        self._pos += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, server: "FakeServer", host: str):
        self.server = server
        self.host = host
        self.closed = False
        self._pending = None

    def request(self, method, path, headers=None):
        self.server.requests.append((self, method, self.host, path, dict(headers or {})))
        self._pending = self.server.handler(self.host, path, dict(headers or {}))
        if isinstance(self._pending, BaseException):
            raise self._pending

    def getresponse(self):
        status, headers, body = self._pending
        return FakeResponse(status, headers, body)

    def close(self):
        self.closed = True


class FakeServer:
    """``handler(host, path, headers)`` returns (status, headers, body) or an exception to raise."""

    def __init__(self, handler):
        self.handler = handler
        self.requests: list = []
        self.connections: list[FakeConnection] = []

    def transport(self, host, timeout, context):
        conn = FakeConnection(self, host)
        self.connections.append(conn)
        return conn

    @classmethod
    def sequence(cls, responses):
        items = list(responses)
        return cls(lambda host, path, headers: items.pop(0))

    @property
    def paths(self):
        return [(r[2], r[3]) for r in self.requests]


def client_for(server, clock=None, *, hosts=("a.example",), max_bytes=1024, rate=1000.0, **kw):
    clock = clock or FakeClock()
    return HttpClient(rate=rate, allowed_hosts=set(hosts), max_bytes=max_bytes, transport=server.transport,
                      sleep=clock.sleep, clock=clock.clock, wall_clock=lambda: 1_700_000_000.0 + clock.now, **kw)


def connector(cls, server, clock=None, rate=1000.0):
    clock = clock or FakeClock()
    return cls(rate=rate, transport=server.transport, sleep=clock.sleep, clock=clock.clock)


OK_JSON = {"Content-Type": "application/json"}


# --------------------------------------------------------------------------- HTTP client

class HttpClientTests(unittest.TestCase):
    def test_user_agent_identifies_with_contact_url(self):
        server = FakeServer.sequence([(200, {}, b"ok")])
        client_for(server).get("https://a.example/x")
        headers = server.requests[0][4]
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertIn("https://", headers["User-Agent"])
        self.assertEqual(headers["Accept-Encoding"], "gzip")

    def test_connection_reused_across_requests(self):
        server = FakeServer(lambda h, p, hd: (200, {}, b"ok"))
        client = client_for(server)
        for i in range(3):
            self.assertEqual(client.get(f"https://a.example/{i}").body, b"ok")
        self.assertEqual(len(server.connections), 1)
        self.assertEqual({id(r[0]) for r in server.requests}, {id(server.connections[0])})

    def test_single_ssl_context_and_verification_on(self):
        import ssl
        contexts = []
        server = FakeServer(lambda h, p, hd: (200, {}, b"ok"))

        def transport(host, timeout, context):
            contexts.append(context)
            return server.transport(host, timeout, context)

        clock = FakeClock()
        client = HttpClient(rate=1000, allowed_hosts={"a.example", "b.example"}, max_bytes=10, transport=transport,
                            sleep=clock.sleep, clock=clock.clock)
        client.get("https://a.example/")
        client.get("https://b.example/")
        self.assertEqual(len(contexts), 2)
        self.assertIs(contexts[0], contexts[1])
        self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(contexts[0].check_hostname)

    def test_separate_connection_per_thread(self):
        server = FakeServer(lambda h, p, hd: (200, {}, b"ok"))
        client = client_for(server)
        client.get("https://a.example/")
        t = threading.Thread(target=lambda: client.get("https://a.example/"))
        t.start()
        t.join()
        self.assertEqual(len(server.connections), 2)

    def test_stale_keepalive_reconnects_without_retry(self):
        calls = {"n": 0}

        def handler(h, p, hd):
            calls["n"] += 1
            if calls["n"] == 2:
                return http.client.RemoteDisconnected("closed")
            return (200, {}, b"ok")

        clock = FakeClock()
        server = FakeServer(handler)
        client = client_for(server, clock)
        client.get("https://a.example/1")
        self.assertEqual(client.get("https://a.example/2").body, b"ok")
        self.assertEqual(len(server.connections), 2)
        self.assertTrue(all(s < 1 for s in clock.sleeps), clock.sleeps)  # rate gate only, no backoff
        self.assertTrue(server.connections[0].closed)

    def test_host_not_allowed_makes_no_request(self):
        server = FakeServer.sequence([])
        with self.assertRaises(SourceError) as cm:
            client_for(server).get("https://evil.example/")
        self.assertEqual(cm.exception.reason, "host_not_allowed")
        with self.assertRaises(SourceError) as cm:
            client_for(server).get("http://a.example/")
        self.assertEqual(cm.exception.reason, "non_https_url")
        self.assertEqual(server.requests, [])

    def test_redirect_followed_to_allowed_host(self):
        server = FakeServer.sequence([
            (302, {"Location": "https://b.example/final?x=1"}, b""),
            (301, {"Location": "/moved"}, b""),
            (200, {}, b"done"),
        ])
        resp = client_for(server, hosts=("a.example", "b.example")).get("https://a.example/start")
        self.assertEqual(resp.body, b"done")
        self.assertEqual(resp.url, "https://b.example/moved")
        self.assertEqual(server.paths, [("a.example", "/start"), ("b.example", "/final?x=1"), ("b.example", "/moved")])

    def test_redirect_to_disallowed_host_is_error(self):
        server = FakeServer.sequence([(302, {"Location": "https://evil.example/x"}, b"")])
        with self.assertRaises(SourceError) as cm:
            client_for(server).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "redirect_host_not_allowed")
        self.assertEqual(len(server.requests), 1)

    def test_redirect_to_http_is_rejected(self):
        server = FakeServer.sequence([(307, {"Location": "http://a.example/plain"}, b"")])
        with self.assertRaises(SourceError) as cm:
            client_for(server).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "redirect_non_https_url")

    def test_too_many_redirects(self):
        server = FakeServer(lambda h, p, hd: (302, {"Location": "/again"}, b""))
        with self.assertRaises(SourceError) as cm:
            client_for(server).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "too_many_redirects")
        self.assertEqual(len(server.requests), 4)

    def test_404_returned_not_retried(self):
        server = FakeServer.sequence([(404, {}, b"nf")])
        resp = client_for(server).get("https://a.example/")
        self.assertEqual((resp.status, resp.body), (404, b"nf"))
        self.assertEqual(len(server.requests), 1)

    def test_5xx_retried_with_backoff_then_success(self):
        clock = FakeClock()
        server = FakeServer.sequence([(503, {}, b""), (502, {}, b""), (200, {}, b"ok")])
        resp = client_for(server, clock).get("https://a.example/")
        self.assertEqual(resp.body, b"ok")
        self.assertEqual(clock.sleeps, [1.0, 2.0])

    def test_retries_exhausted(self):
        clock = FakeClock()
        server = FakeServer(lambda h, p, hd: (500, {}, b"boom"))
        with self.assertRaises(SourceError) as cm:
            client_for(server, clock).get("https://a.example/?token=secret")
        self.assertEqual(cm.exception.reason, "http_500")
        self.assertNotIn("secret", str(cm.exception))
        self.assertEqual(clock.sleeps, [1.0, 2.0, 4.0, 8.0])
        self.assertEqual(len(server.requests), 5)

    def test_timeout_retried_then_error(self):
        clock = FakeClock()
        server = FakeServer(lambda h, p, hd: TimeoutError("timed out"))
        with self.assertRaises(SourceError) as cm:
            client_for(server, clock, max_retries=2).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "timeout")
        self.assertEqual(clock.sleeps, [1.0, 2.0])

    def test_connection_error_retried(self):
        clock = FakeClock()
        server = FakeServer.sequence([ConnectionRefusedError("refused"), (200, {}, b"ok")])
        self.assertEqual(client_for(server, clock).get("https://a.example/").body, b"ok")
        self.assertEqual(clock.sleeps, [1.0])

    def test_429_retry_after_seconds_shared_cooldown(self):
        clock = FakeClock()
        server = FakeServer.sequence([(429, {"Retry-After": "7"}, b""), (200, {}, b"ok"), (200, {}, b"ok2")])
        client = client_for(server, clock)
        start = clock.now
        self.assertEqual(client.get("https://a.example/").body, b"ok")
        self.assertAlmostEqual(clock.now - start, 7.0)
        # The cooldown lives in the shared gate: a second caller set before expiry also waits.
        client.gate.cooldown(5)
        before = clock.now
        t = threading.Thread(target=lambda: client.get("https://a.example/other"))
        t.start()
        t.join()
        self.assertGreaterEqual(clock.now - before, 5.0)

    def test_429_retry_after_http_date(self):
        clock = FakeClock()
        wall = 1_700_000_000.0 + clock.now
        date = formatdate(wall + 120, usegmt=True)
        server = FakeServer.sequence([(429, {"Retry-After": date}, b""), (200, {}, b"ok")])
        client_for(server, clock).get("https://a.example/")
        self.assertAlmostEqual(sum(clock.sleeps), 120.0, delta=1.0)

    def test_retry_after_parsing(self):
        self.assertEqual(parse_retry_after(None, 0), 30.0)
        self.assertEqual(parse_retry_after("garbage", 0), 30.0)
        self.assertEqual(parse_retry_after("0", 0), 1.0)
        self.assertEqual(parse_retry_after("99999", 0), 3600.0)
        self.assertEqual(parse_retry_after(formatdate(100, usegmt=True), 200), 1.0)

    def test_429_cooldown_blocks_other_threads(self):
        clock = FakeClock()
        gate = RateGate(1000, clock=clock.clock, sleep=clock.sleep)
        gate.cooldown(30)
        gate.acquire()
        self.assertGreaterEqual(clock.now, 1030.0)

    def test_429_exhausted(self):
        clock = FakeClock()
        server = FakeServer(lambda h, p, hd: (429, {"Retry-After": "2"}, b""))
        with self.assertRaises(SourceError) as cm:
            client_for(server, clock, max_retries=2).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "rate_limited")
        self.assertEqual(len(server.requests), 3)

    def test_rate_gate_spacing(self):
        clock = FakeClock()
        server = FakeServer(lambda h, p, hd: (200, {}, b"ok"))
        client = client_for(server, clock, rate=0.5)
        starts = []
        orig = server.handler
        server.handler = lambda h, p, hd: (starts.append(clock.now), orig(h, p, hd))[1]
        for _ in range(3):
            client.get("https://a.example/")
        self.assertEqual([round(b - a, 6) for a, b in zip(starts, starts[1:])], [2.0, 2.0])

    def test_body_too_large(self):
        server = FakeServer.sequence([(200, {}, b"x" * 1025)])
        with self.assertRaises(SourceError) as cm:
            client_for(server, max_bytes=1024).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "response_too_large")
        self.assertTrue(server.connections[0].closed)

    def test_body_at_limit_ok(self):
        server = FakeServer.sequence([(200, {}, b"x" * 1024)])
        self.assertEqual(len(client_for(server, max_bytes=1024).get("https://a.example/").body), 1024)

    def test_gzip_decoded(self):
        server = FakeServer.sequence([(200, {"Content-Encoding": "gzip"}, gzip.compress(b"hello" * 10))])
        self.assertEqual(client_for(server).get("https://a.example/").body, b"hello" * 10)

    def test_gzip_bomb_capped(self):
        server = FakeServer.sequence([(200, {"Content-Encoding": "gzip"}, gzip.compress(b"\0" * 100_000))])
        with self.assertRaises(SourceError) as cm:
            client_for(server, max_bytes=1024).get("https://a.example/")
        self.assertEqual(cm.exception.reason, "response_too_large")


# --------------------------------------------------------------------------- connectors

def routes(table):
    def handler(host, path, headers):
        key = (host, path)
        if key not in table:
            return (500, {}, b"unexpected " + repr(key).encode())
        return table[key]
    return handler


class CTTests(unittest.TestCase):
    SUB = ("crt.sh", "/?q=%25.example.com&output=json")
    APEX = ("crt.sh", "/?q=example.com&output=json")

    def test_mapping_merges_and_normalizes(self):
        sub, apex = fixture("crtsh_subdomains.json"), fixture("crtsh_apex.json")
        server = FakeServer(routes({self.SUB: (200, OK_JSON, sub), self.APEX: (200, OK_JSON, apex)}))
        res = connector(CTConnector, server).fetch("Example.COM.")
        self.assertEqual(res.status, "ok", res.error)
        self.assertEqual(res.query, "example.com")
        self.assertEqual(res.source_url, "https://crt.sh/?q=%25.example.com&output=json")
        self.assertEqual(res.raw_sha256, hashlib.sha256(sub + b"\n" + apex).hexdigest())
        certs = res.data["certificates"]
        self.assertEqual([c["id"] for c in certs], ["42", "555", "1234567", "9876543210"])
        by_id = {c["id"]: c for c in certs}
        self.assertEqual(by_id["9876543210"]["names"], ["example.com", "www.example.com"])
        self.assertEqual(by_id["1234567"]["names"], ["*.example.com", "example.com", "mail.example.com"])
        self.assertEqual(by_id["9876543210"]["not_before"], "2024-03-01T09:12:13+00:00")
        self.assertEqual(by_id["9876543210"]["not_after"], "2024-05-30T09:12:12+00:00")
        self.assertEqual(by_id["42"]["issuer"], "C=US, O=Google Trust Services, CN=WR1")
        self.assertRegex(res.retrieved_at, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")

    def test_empty_is_no_record(self):
        server = FakeServer(routes({self.SUB: (200, OK_JSON, b"[]"), self.APEX: (200, OK_JSON, b"[]")}))
        res = connector(CTConnector, server).fetch("example.com")
        self.assertEqual((res.status, res.data), ("no_record", {}))

    def test_html_error_page_is_error(self):
        server = FakeServer(routes({self.SUB: (200, {"Content-Type": "text/html"}, fixture("crtsh_error.html"))}))
        res = connector(CTConnector, server).fetch("example.com")
        self.assertEqual((res.status, res.error, res.data), ("error", "not_json", {}))
        self.assertIsNotNone(res.raw_sha256)

    def test_invalid_query_no_request(self):
        server = FakeServer.sequence([])
        for bad in ("", "not a domain", "198.51.100.1", "*.example.com", "localhost", "a..b"):
            res = connector(CTConnector, server).fetch(bad)
            self.assertEqual((res.status, res.error), ("error", "invalid_query"), bad)
        self.assertEqual(server.requests, [])


class DNSTests(unittest.TestCase):
    def path(self, name):
        return ("cloudflare-dns.com", f"/dns-query?name={name}&type=A")

    def test_cname_chain_and_addresses(self):
        body = fixture("doh_cname_chain.json")
        server = FakeServer(routes({self.path("www.example.com"): (200, {}, body)}))
        res = connector(DNSConnector, server).fetch("WWW.example.com")
        self.assertEqual(res.status, "ok", res.error)
        self.assertEqual(res.data, {
            "name": "www.example.com",
            "cnames": ["www.example.com.cdn.example.net", "edge-7.cdn.example.net"],
            "addresses": ["198.51.100.9", "203.0.113.10"],
            "ttl": 20,
        })
        self.assertEqual(server.requests[0][4]["Accept"], "application/dns-json")
        self.assertEqual(res.raw_sha256, hashlib.sha256(body).hexdigest())

    def test_nxdomain_and_nodata_are_no_record(self):
        server = FakeServer(routes({
            self.path("nope.example.com"): (200, {}, fixture("doh_nxdomain.json")),
            self.path("v6only.example.com"): (200, {}, fixture("doh_noerror_nodata.json")),
        }))
        conn = connector(DNSConnector, server)
        for name in ("nope.example.com", "v6only.example.com"):
            res = conn.fetch(name)
            self.assertEqual((res.status, res.data), ("no_record", {}), name)

    def test_servfail_is_error(self):
        server = FakeServer(routes({self.path("broken.example.com"): (200, {}, fixture("doh_servfail.json"))}))
        res = connector(DNSConnector, server).fetch("broken.example.com")
        self.assertEqual((res.status, res.error), ("error", "dns_rcode_2"))

    def test_invalid_query_no_request(self):
        server = FakeServer.sequence([])
        for bad in ("exa mple.com", "-bad.example.com", "x" * 64 + ".com", "1.2.3.4", "a.b/c"):
            self.assertEqual(connector(DNSConnector, server).fetch(bad).error, "invalid_query", bad)
        self.assertEqual(server.requests, [])


class RDAPTests(unittest.TestCase):
    def test_arin_via_redirect(self):
        body = fixture("rdap_arin.json")
        server = FakeServer(routes({
            ("rdap.org", "/ip/198.51.100.9"): (302, {"Location": "https://rdap.arin.net/registry/ip/198.51.100.9"}, b""),
            ("rdap.arin.net", "/registry/ip/198.51.100.9"): (200, {"Content-Type": "application/rdap+json"}, body),
        }))
        res = connector(RDAPConnector, server).fetch("198.51.100.9")
        self.assertEqual(res.status, "ok", res.error)
        self.assertEqual(res.source_url, "https://rdap.org/ip/198.51.100.9")
        self.assertEqual(res.raw_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(res.data, {
            "handle": "NET-198-51-100-0-1",
            "network_name": "EXAMPLE-NET",
            "cidrs": ["198.51.100.0/24"],
            "org_names": ["Example Corp"],
            "entity_handles": ["ABUSE1234-ARIN", "EXMPL-1", "NOC99-ARIN"],
            "country": None,
            "registration_date": "2012-02-24T21:22:10+00:00",
            "last_changed": "2023-07-12T13:15:03+00:00",
        })

    def test_ripe_without_cidr0(self):
        server = FakeServer(routes({
            ("rdap.org", "/ip/203.0.113.7"): (301, {"Location": "https://rdap.db.ripe.net/ip/203.0.113.7"}, b""),
            ("rdap.db.ripe.net", "/ip/203.0.113.7"): (200, {}, fixture("rdap_ripe.json")),
        }))
        res = connector(RDAPConnector, server).fetch("203.0.113.7")
        self.assertEqual(res.status, "ok", res.error)
        d = res.data
        self.assertEqual(d["cidrs"], ["203.0.113.0/25"])
        self.assertEqual(d["org_names"], ["Example B.V."])
        self.assertEqual(d["entity_handles"], ["AR123-RIPE", "EXA-RIPE", "EXAMPLE-MNT", "ORG-EXA1-RIPE"])
        self.assertEqual(d["country"], "NL")
        self.assertEqual(d["registration_date"], "2015-03-10T11:20:49+00:00")
        self.assertEqual(d["last_changed"], "2021-11-02T08:01:00+00:00")
        self.assertEqual(d["handle"], "203.0.113.0 - 203.0.113.127")

    def test_no_registrant_falls_back_excluding_abuse(self):
        server = FakeServer(routes({("rdap.org", "/ip/192.0.2.1"): (200, {}, fixture("rdap_no_registrant.json"))}))
        d = connector(RDAPConnector, server).fetch("192.0.2.1").data
        self.assertEqual(d["org_names"], ["Hosting Ltd", "Ops"])
        self.assertEqual(d["cidrs"], ["192.0.2.0/24"])

    def test_404_no_record(self):
        server = FakeServer(routes({("rdap.org", "/ip/192.0.2.1"): (404, {}, fixture("rdap_not_found.json"))}))
        res = connector(RDAPConnector, server).fetch("192.0.2.1")
        self.assertEqual((res.status, res.data, res.error), ("no_record", {}, None))

    def test_redirect_to_unknown_host_is_error(self):
        server = FakeServer(routes({
            ("rdap.org", "/ip/192.0.2.1"): (302, {"Location": "https://rdap.attacker.example/ip/192.0.2.1"}, b""),
        }))
        res = connector(RDAPConnector, server).fetch("192.0.2.1")
        self.assertEqual((res.status, res.error), ("error", "redirect_host_not_allowed"))

    def test_invalid_query_no_request(self):
        server = FakeServer.sequence([])
        for bad in ("example.com", "198.51.100.0/24", "2001:db8::1", "256.1.1.1", "01.2.3.4"):
            self.assertEqual(connector(RDAPConnector, server).fetch(bad).error, "invalid_query", bad)
        self.assertEqual(server.requests, [])


class InternetDBTests(unittest.TestCase):
    def test_found(self):
        body = fixture("internetdb_found.json")
        server = FakeServer(routes({("internetdb.shodan.io", "/198.51.100.9"): (200, OK_JSON, body)}))
        res = connector(InternetDBConnector, server).fetch("198.51.100.9")
        self.assertEqual(res.status, "ok", res.error)
        self.assertEqual(res.source_url, "https://internetdb.shodan.io/198.51.100.9")
        self.assertEqual(res.raw_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(res.data, {
            "ports": [22, 80, 443],
            "hostnames": ["portal.example.com", "www.example.com"],
            "cpes": ["cpe:/a:nginx:nginx:1.18.0", "cpe:/o:canonical:ubuntu_linux"],
            "tags": ["cloud"],
            "vulns": ["CVE-2019-20372", "CVE-2021-23017"],
        })

    def test_404_no_record(self):
        server = FakeServer(routes({("internetdb.shodan.io", "/192.0.2.1"): (404, OK_JSON, fixture("internetdb_not_found.json"))}))
        res = connector(InternetDBConnector, server).fetch("192.0.2.1")
        self.assertEqual((res.status, res.data), ("no_record", {}))
        self.assertIsNotNone(res.raw_sha256)

    def test_ip_mismatch_is_error(self):
        server = FakeServer(routes({("internetdb.shodan.io", "/192.0.2.1"): (200, OK_JSON, fixture("internetdb_found.json"))}))
        res = connector(InternetDBConnector, server).fetch("192.0.2.1")
        self.assertEqual((res.status, res.error), ("error", "unexpected_response"))

    def test_list_cap(self):
        import json
        body = json.dumps({"ip": "192.0.2.1", "ports": list(range(1500)), "hostnames": [], "cpes": [],
                           "tags": [], "vulns": [f"CVE-2020-{i:05d}" for i in range(1200)]}).encode()
        server = FakeServer(routes({("internetdb.shodan.io", "/192.0.2.1"): (200, OK_JSON, body)}))
        d = connector(InternetDBConnector, server).fetch("192.0.2.1").data
        self.assertEqual(len(d["ports"]), 1000)
        self.assertEqual(len(d["vulns"]), 1000)

    def test_retries_exhausted_is_error_result(self):
        clock = FakeClock()
        server = FakeServer(lambda h, p, hd: (503, {}, b""))
        res = connector(InternetDBConnector, server, clock).fetch("192.0.2.1")
        self.assertEqual((res.status, res.error, res.data), ("error", "http_503", {}))
        self.assertIsNone(res.raw_sha256)
        self.assertEqual(len(server.requests), 5)

    def test_too_large_is_error_result(self):
        server = FakeServer(lambda h, p, hd: (200, {}, b" " * (64 * 1024 + 1)))
        res = connector(InternetDBConnector, server).fetch("192.0.2.1")
        self.assertEqual((res.status, res.error), ("error", "response_too_large"))

    def test_invalid_query_no_request(self):
        server = FakeServer.sequence([])
        self.assertEqual(connector(InternetDBConnector, server).fetch("example.com").error, "invalid_query")
        self.assertEqual(server.requests, [])


class LiveConnectorsTests(unittest.TestCase):
    def test_live_connectors_construct(self):
        from averiguao_core.connectors import live_connectors
        conns = live_connectors({"dns": 3})
        self.assertEqual(set(conns), {"ct", "dns", "rdap", "internetdb"})
        self.assertEqual(conns["dns"].client.gate.interval, 1 / 3)
        self.assertEqual(conns["ct"].client.gate.interval, 2.0)
        for name, conn in conns.items():
            self.assertEqual(conn.name, name)


if __name__ == "__main__":
    unittest.main()
