"""G3 adversarial probes: source etiquette and robustness (rate limits, 429, retries, allowlist, failures).

Tests whose docstring starts with "ISSUE" fail on purpose and document a confirmed problem. The rest are regression
guards. No sockets: an injected transport serves canned responses and a fake clock replaces sleeping.
"""

from __future__ import annotations

import gzip
import json
import threading
import unittest

from averiguao_core import attribution, reports
from averiguao_core.connectors import live_connectors
from averiguao_core.connectors.ct import CTConnector
from averiguao_core.connectors.dns import DNSConnector
from averiguao_core.connectors.http import HttpClient, RateGate, SourceError
from averiguao_core.connectors.internetdb import InternetDBConnector
from averiguao_core.connectors.rdap import RDAPConnector
from averiguao_core.contracts import USER_AGENT

from ._world import WorldCase, a, cert, queried, rdap, world


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []
        self._lock = threading.Lock()

    def clock(self):
        with self._lock:
            return self.now

    def sleep(self, s):
        with self._lock:
            self.sleeps.append(s)
            self.now += s


class Resp:
    def __init__(self, status, headers, body):
        self.status, self._h, self._b, self._p = status, headers, body, 0

    def getheaders(self):
        return list(self._h.items())

    def read(self, amt=None):
        end = len(self._b) if amt is None else self._p + amt
        out = self._b[self._p:end]
        self._p += len(out)
        return out


class Server:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []
        self.opened = []
        self._lock = threading.Lock()

    def transport(self, host, timeout, ctx):
        server = self

        class Conn:
            def request(self, method, path, headers=None):
                with server._lock:
                    server.requests.append((host, path, dict(headers or {}), timeout))
                self.pending = server.handler(host, path)
                if isinstance(self.pending, BaseException):
                    raise self.pending

            def getresponse(self):
                return Resp(*self.pending)

            def close(self):
                pass

        with self._lock:
            self.opened.append(host)
        return Conn()


def client(server, clock, hosts=("api.test",), **kw):
    return HttpClient(rate=kw.pop("rate", 1000.0), allowed_hosts=set(hosts), max_bytes=kw.pop("max_bytes", 4096),
                      transport=server.transport, sleep=clock.sleep, clock=clock.clock,
                      wall_clock=lambda: 1_700_000_000.0, **kw)


class HttpEtiquette(unittest.TestCase):
    def test_retries_are_bounded_for_5xx_timeouts_and_429(self):
        for handler in (lambda h, p: (503, {}, b""), lambda h, p: TimeoutError(), lambda h, p: (429, {}, b"")):
            clock, server = FakeClock(), Server(handler)
            with self.assertRaises(SourceError):
                client(server, clock).get("https://api.test/x")
            self.assertEqual(len(server.requests), 5)  # 1 + max_retries(4)

    def test_single_request_cannot_block_for_hours_on_retry_after(self):
        """ISSUE (http.py HttpClient.get ~line 835-840 with parse_retry_after clamp 3600): a source answering 429
        with 'Retry-After: 3600' four times makes one connector call sleep 4 x 3600 s = 4 hours inside a worker
        thread. The engine checks max_seconds and the pause/stop event only between batches, so during that time
        the run can neither be paused nor stopped and overshoots max_seconds by hours. RULES.md is silent; common
        sense: a cooldown longer than a few minutes (or the cumulative wait of one call) should give up with
        'rate_limited' (an error the run reports) instead of blocking, or the wait must observe the stop event."""
        clock, server = FakeClock(), Server(lambda h, p: (429, {"Retry-After": "3600"}, b""))
        with self.assertRaises(SourceError):
            client(server, clock).get("https://api.test/x")
        self.assertLessEqual(sum(clock.sleeps), 900, f"one call slept {sum(clock.sleeps):.0f}s")

    def test_429_cooldown_holds_back_other_threads(self):
        clock = FakeClock()
        gate = RateGate(1000.0, clock=clock.clock, sleep=clock.sleep)
        gate.acquire()
        gate.cooldown(30)
        gate.acquire()
        self.assertGreaterEqual(clock.now, 1030.0)

    def test_rate_gate_is_shared_by_threads_of_one_client(self):
        clock = FakeClock()
        gate = RateGate(2.0, clock=clock.clock, sleep=clock.sleep)
        starts = []
        lock = threading.Lock()

        def go():
            gate.acquire()
            with lock:
                starts.append(clock.clock())

        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        starts.sort()
        gaps = [b - a_ for a_, b in zip(starts, starts[1:])]
        self.assertTrue(all(g >= 0.5 - 1e-9 for g in gaps), gaps)

    def test_live_connector_factory_keeps_rate_state_across_resumes(self):
        """ISSUE (cli.py line 100 `lambda: live_connectors(rates)` + runner.py _work line ~608 calling
        self.connectors() on every execute): every pause/resume (and every new run) builds brand-new HttpClients,
        so each source's RateGate and any 429 cooldown the source imposed are forgotten. A source that just
        asked for 'Retry-After: 600' is hit again immediately after a resume, and back-to-back runs restart the
        spacing at zero. Rate state must be per source for the process (RULES.md 8 names fixed public sources),
        not per execute call."""
        first, second = live_connectors(), live_connectors()
        for name in ("ct", "dns", "rdap", "internetdb"):
            self.assertIs(first[name].client.gate, second[name].client.gate, name)

    def test_redirects_off_the_allowlist_are_refused(self):
        for location in ("https://evil.test/ip/1", "//evil.test/x", "http://api.test/x", "https://api.test:8443/x",
                         "https://api.test@evil.test/x", "https://evil.test#@api.test/", "https://API.TEST./x",
                         "https://198.51.100.7/x"):
            clock = FakeClock()
            server = Server(lambda h, p, loc=location: (302, {"Location": loc}, b"") if p == "/start" else (200, {}, b"ok"))
            with self.assertRaises(SourceError, msg=location):
                client(server, clock).get("https://api.test/start")
            self.assertEqual({r[0] for r in server.requests}, {"api.test"}, location)

    def test_user_agent_timeout_and_connection_reuse(self):
        clock, server = FakeClock(), Server(lambda h, p: (200, {}, b"ok"))
        c = client(server, clock, timeout=7)
        c.get("https://api.test/a")
        c.get("https://api.test/b")
        self.assertEqual(len(server.opened), 1)
        self.assertTrue(all(r[2]["User-Agent"] == USER_AGENT for r in server.requests))
        self.assertTrue(all(r[3] == 7 for r in server.requests))

    def test_body_and_gzip_caps(self):
        clock = FakeClock()
        big = Server(lambda h, p: (200, {}, b"x" * 5000))
        with self.assertRaises(SourceError):
            client(big, clock).get("https://api.test/x")
        bomb = gzip.compress(b"\0" * 10_000_000)
        gz = Server(lambda h, p: (200, {"Content-Encoding": "gzip"}, bomb))
        with self.assertRaises(SourceError):
            client(gz, clock).get("https://api.test/x")


class ConnectorsNeverContactInvestigatedHosts(unittest.TestCase):
    def test_every_request_goes_to_its_source_host_only(self):
        clock = FakeClock()
        server = Server(lambda h, p: (404, {}, b"{}"))
        conns = [cls(rate=1000.0, transport=server.transport, sleep=clock.sleep, clock=clock.clock)
                 for cls in (CTConnector, DNSConnector, RDAPConnector, InternetDBConnector)]
        for q in ("www.example.com", "198.51.100.7", "evil.test/../x", "example.com@evil.test", "evil.test:80",
                  "%2e%2e", "198.51.100.7#@evil.test"):
            for c in conns:
                c.fetch(q)
        allowed = {"crt.sh", "cloudflare-dns.com", "rdap.org", "internetdb.shodan.io"}
        self.assertTrue({r[0] for r in server.requests} <= allowed, {r[0] for r in server.requests})

    def test_hostile_json_never_raises_from_fetch(self):
        clock = FakeClock()
        nested = b"[" * 100_000 + b"]" * 100_000
        bodies = [nested, b"NaN", b'{"ip": "198.51.100.7", "hostnames": [null, 1, {"a": 1}, "WWW.EXAMPLE.COM."]}',
                  b'[{"id": NaN, "name_value": null}, {"id": 1e999, "name_value": 7}]', b"\xff\xfe", b"null",
                  json.dumps({"Status": True, "Answer": [{"type": 1, "data": None}]}).encode()]
        for body in bodies:
            server = Server(lambda h, p, b=body: (200, {}, b))
            for cls, q in ((CTConnector, "example.com"), (DNSConnector, "example.com"),
                           (RDAPConnector, "198.51.100.7"), (InternetDBConnector, "198.51.100.7")):
                c = cls(rate=1000.0, transport=server.transport, sleep=clock.sleep, clock=clock.clock)
                res = c.fetch(q)
                self.assertIn(res.status, ("ok", "no_record", "error"))


class SourceDownForWholeRun(WorldCase):
    def test_every_source_down_is_flagged_not_clean(self):
        down = lambda q: "error"  # noqa: E731
        w = world(dns={"example.com": a("example.com", ["198.51.100.9"])}, rdap_fallback=down)
        for name in ("ct", "internetdb"):
            w[name].fallback = down
        store, run_id = self.run_world("example.com\n198.51.100.0/30", w)
        attribution.assess_run(store, run_id)
        store.set_status(run_id, "complete")
        run = store.run(run_id)
        self.assertEqual(set(run["source_failures"]), {"ct", "rdap", "internetdb"})
        md = b"".join(reports.markdown_report(store, run_id)).decode("utf-8")
        if md is not None:
            self.assertIn("Source failures", md)
        flagged = [f for f in store.findings(run_id)[0] if "source_error" in f.flags]
        self.assertTrue(flagged)

    def test_rdap_hits_within_one_batch_reuse_the_first_answer(self):
        """ISSUE (engine.py execute ~line 410-431): the RDAP cache is built from the store once per batch, so all
        RDAP tasks in the same batch are fired in parallel even when they sit in one network. A domain resolving
        to 20 addresses in one /24 costs 20 rdap.org lookups (default rate 1/s) instead of 1. RULES.md 2 says an
        ip inside an already-fetched RDAP network reuses that evidence 'without a query'; the engine should
        resolve RDAP tasks of a batch sequentially (or re-check the cache after each answer) so a network is
        fetched once per run."""
        ips = [f"198.51.100.{i}" for i in range(1, 21)]
        w = world(dns={"example.com": a("example.com", ips)},
                  rdap_fallback=lambda q: rdap("CORP-NET", ["198.51.100.0/24"]))
        self.run_world("example.com", w)
        self.assertLessEqual(len(w["rdap"].queries()), 2, w["rdap"].queries())


if __name__ == "__main__":
    unittest.main()
