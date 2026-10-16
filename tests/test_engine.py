"""Engine tests (docs/RULES.md section 2) on small hand-built FakeConnector worlds. No network."""

from __future__ import annotations

import random
import tempfile
import threading
import time
import unittest
from pathlib import Path

from averiguao_core import attribution, engine, scope
from averiguao_core.connectors.fake import FakeConnector
from averiguao_core.store import Store

CLOCK = "2026-10-01T00:00:00+00:00"
CORP_RDAP = {"handle": "NET-CORP", "network_name": "CORP-NET", "cidrs": ["198.51.100.0/24"], "org_names": ["Corp"],
             "entity_handles": ["CORP-1"], "country": "US", "registration_date": None, "last_changed": None}


def cert(cid, names, not_before="2026-01-01T00:00:00+00:00", not_after="2027-01-01T00:00:00+00:00"):
    return {"id": cid, "names": names, "not_before": not_before, "not_after": not_after, "issuer": "CA"}


def a(name, addresses, cnames=()):
    return {"name": name, "cnames": list(cnames), "addresses": list(addresses), "ttl": 300}


def idb(ports=(), hostnames=(), vulns=()):
    return {"ports": list(ports), "hostnames": list(hostnames), "cpes": [], "tags": [], "vulns": list(vulns)}


def world(ct=None, dns=None, rdap=None, internetdb=None, on_call=None, rdap_fallback=None):
    return {
        "ct": FakeConnector("ct", ct or {}, clock=CLOCK, on_call=on_call),
        "dns": FakeConnector("dns", dns or {}, clock=CLOCK, on_call=on_call),
        "rdap": FakeConnector("rdap", rdap or {}, clock=CLOCK, on_call=on_call, fallback=rdap_fallback),
        "internetdb": FakeConnector("internetdb", internetdb or {}, clock=CLOCK, on_call=on_call),
    }


class EngineCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="averiguao-engine-")
        self.addCleanup(self._tmp.cleanup)
        self._n = 0

    def make_run(self, seeds, limits=None, org_names=("Corp",), match_rules=None):
        self._n += 1
        store = Store(Path(self._tmp.name) / f"db{self._n}.sqlite3")
        body = {"seeds": seeds, "approval_ref": "TICKET-1", "org_names": list(org_names), "limits": limits or {}}
        if match_rules:
            body["match_rules"] = match_rules
        config = scope.parse_run_config(body, allow_documentation_ranges=True)
        return store, store.create_run(config)

    def run_world(self, seeds, w, *, limits=None, workers=4, batch_size=64, **kw):
        store, run_id = self.make_run(seeds, limits, **kw)
        status = engine.execute(store, run_id, w, threading.Event(), workers=workers, batch_size=batch_size)
        self.assertEqual(status, "done")
        return store, run_id

    @staticmethod
    def asset_ids(store, run_id):
        return {r["asset"].id for r in store.assets(run_id)}

    @staticmethod
    def rels(store, run_id):
        return {(r.subject_id, r.predicate, r.object_id): r for r in store.relationships(run_id)}


class TestSeeding(EngineCase):
    def test_domain_seed(self):
        store, run_id = self.run_world("example.com", world())
        rows = store.assets(run_id)
        self.assertEqual([r["asset"].id for r in rows], ["domain:example.com"])
        self.assertEqual(rows[0]["depth"], 0)
        rel = self.rels(store, run_id)[("seed:1", "seed_is", "domain:example.com")]
        self.assertEqual(rel.evidence_ids, ("ev:seed:1",))
        ev = store.evidence(run_id, ["ev:seed:1"])[0]
        self.assertEqual((ev.source, ev.query), ("scope", "example.com"))
        self.assertEqual(ev.data, {"approval_ref": "TICKET-1", "scope_version": "1", "seed_type": "domain"})

    def test_ip_seed_enrichment_only(self):
        w = world(rdap={"198.51.100.7": CORP_RDAP}, internetdb={"198.51.100.7": idb(ports=[443])})
        store, run_id = self.run_world("198.51.100.7", w)
        self.assertEqual(self.asset_ids(store, run_id), {"ip:198.51.100.7"})
        self.assertEqual(w["rdap"].queries(), ["198.51.100.7"])
        self.assertEqual(w["internetdb"].queries(), ["198.51.100.7"])
        self.assertEqual(w["ct"].queries() + w["dns"].queries(), [])
        rd = [e for e in store.evidence(run_id) if e.source == "rdap"][0]
        self.assertEqual(rd.source_record_id, "NET-CORP")

    def test_prefix_seed_coverage_and_members(self):
        w = world(internetdb={"198.51.100.1": idb(ports=[22]), "198.51.100.2": "error"},
                  rdap_fallback=lambda q: CORP_RDAP)
        store, run_id = self.run_world("198.51.100.0/30", w)
        self.assertEqual(sorted(w["internetdb"].queries()), [f"198.51.100.{i}" for i in range(4)])
        self.assertEqual(w["rdap"].queries(), ["198.51.100.0"])  # network rdap once, no per-member rdap
        self.assertEqual(self.asset_ids(store, run_id), {"ip:198.51.100.1"})
        rel = self.rels(store, run_id)[("seed:1", "prefix_contains_ip", "ip:198.51.100.1")]
        self.assertEqual(rel.depth, 1)
        cov = {c["ip"]: c["status"] for c in store.coverage(run_id)}
        self.assertEqual(cov, {"198.51.100.0": "no_record", "198.51.100.1": "ok", "198.51.100.2": "error",
                               "198.51.100.3": "no_record"})
        run = store.run(run_id)
        self.assertEqual(run["source_failures"], {"internetdb": 1})
        errs = [e for e in store.evidence(run_id) if e.data.get("status") == "error"]
        self.assertEqual([e.query for e in errs], ["198.51.100.2"])
        # no_record prefix members go to coverage only
        self.assertFalse([e for e in store.evidence(run_id) if e.data.get("status") == "no_record"])


class TestResultHandling(EngineCase):
    def test_ct_rules(self):
        w = world(ct={"example.com": {"certificates": [
            cert("1", ["example.com", "*.example.com"]),
            cert("2", ["www.example.com", "*.api.example.com"]),
            cert("3", ["example.com", "shop.other.test", "example.com.evil.test"]),
            cert("4", ["www.example.com"]),
        ]}}, dns={"www.example.com": "no_record", "api.example.com": "no_record"})
        store, run_id = self.run_world("example.com", w)
        self.assertEqual(self.asset_ids(store, run_id),
                         {"domain:example.com", "hostname:www.example.com", "hostname:api.example.com"})
        ct_evs = [e for e in store.evidence(run_id) if e.source == "ct"]
        self.assertEqual(sorted(e.source_record_id for e in ct_evs), ["1", "2", "3", "4"])
        for e in ct_evs:
            self.assertEqual(e.valid_from, "2026-01-01T00:00:00+00:00")
            self.assertEqual(e.valid_to, "2027-01-01T00:00:00+00:00")
            self.assertEqual(e.data["query"], "example.com")
        rel = self.rels(store, run_id)[("domain:example.com", "certificate_mentions_hostname",
                                        "hostname:www.example.com")]
        self.assertEqual(len(rel.evidence_ids), 2)  # repeated observation appends evidence
        self.assertEqual(rel.depth, 1)
        self.assertEqual(sorted(w["dns"].queries()), ["api.example.com", "example.com", "www.example.com"])
        self.assertEqual(store.run(run_id)["out_of_scope"], {"ct_name_outside_approved_domains": 2})
        dns_nr = [e for e in store.evidence(run_id) if e.source == "dns"]
        self.assertTrue(all(e.data == {"status": "no_record"} for e in dns_nr))

    def test_dns_rules_and_cname_context(self):
        w = world(dns={"example.com": a("example.com", ["198.51.100.2", "198.51.100.3"], ["lb.example.com"])},
                  rdap={"198.51.100.2": CORP_RDAP})
        store, run_id = self.run_world("example.com", w)
        self.assertEqual(self.asset_ids(store, run_id),
                         {"domain:example.com", "ip:198.51.100.2", "ip:198.51.100.3"})
        rels = self.rels(store, run_id)
        self.assertIn(("domain:example.com", "hostname_resolves_to_ip", "ip:198.51.100.2"), rels)
        self.assertFalse([k for k in rels if "lb.example.com" in k[2]])  # CNAME: no relationship
        dns = [e for e in store.evidence(run_id) if e.source == "dns"][0]
        self.assertEqual(dns.data["cnames"], ["lb.example.com"])
        self.assertEqual(sorted(w["rdap"].queries()), ["198.51.100.2", "198.51.100.3"])  # same batch: cache only applies to later batches
        self.assertEqual(sorted(w["internetdb"].queries()), ["198.51.100.2", "198.51.100.3"])

    def test_depth_limit(self):
        w = world(ct={"example.com": {"certificates": [cert("1", ["www.example.com"])]}},
                  dns={"www.example.com": a("www.example.com", ["198.51.100.9"]),
                       "example.com": a("example.com", ["198.51.100.2"])})
        store, run_id = self.run_world("example.com", w, limits={"max_depth": 1})
        ids = self.asset_ids(store, run_id)
        self.assertIn("hostname:www.example.com", ids)
        self.assertIn("ip:198.51.100.2", ids)
        self.assertNotIn("ip:198.51.100.9", ids)
        self.assertNotIn("198.51.100.9", w["rdap"].queries() + w["internetdb"].queries())
        self.assertEqual(store.run(run_id)["out_of_scope"], {"depth_limit": 1})

    def test_internetdb_hostnames(self):
        w = world(rdap={"198.51.100.7": CORP_RDAP},
                  internetdb={"198.51.100.7": idb(hostnames=["vpn.example.com", "tenant.other.test"])},
                  dns={"example.com": a("example.com", ["198.51.100.7"])})
        store, run_id = self.run_world("example.com", w)
        ids = self.asset_ids(store, run_id)
        self.assertIn("hostname:vpn.example.com", ids)
        self.assertNotIn("hostname:tenant.other.test", ids)
        self.assertNotIn("vpn.example.com", w["dns"].queries())  # RECORD, no DNS task
        rel = self.rels(store, run_id)[("ip:198.51.100.7", "ip_reports_hostname", "hostname:vpn.example.com")]
        self.assertEqual(rel.depth, 1)  # enrichment never increases depth
        self.assertEqual(store.run(run_id)["out_of_scope"], {})  # out-of-scope tenant is CONTEXT, not DENY

    def test_source_errors_are_evidence(self):
        w = world(ct={"example.com": "error"}, dns={"example.com": "error"})
        store, run_id = self.run_world("example.com", w)
        self.assertEqual(store.run(run_id)["source_failures"], {"ct": 1, "dns": 1})
        errs = [e for e in store.evidence(run_id) if e.data.get("status") == "error"]
        self.assertEqual(sorted(e.source for e in errs), ["ct", "dns"])

    def test_rdap_cache_reused_across_batches(self):
        w = world(dns={"example.com": a("example.com", [f"198.51.100.{i}" for i in (2, 3, 4)])},
                  rdap_fallback=lambda q: CORP_RDAP)
        store, run_id = self.run_world("example.com", w, batch_size=1, workers=1)
        self.assertEqual(w["rdap"].queries(), ["198.51.100.2"])
        run = store.run(run_id)
        self.assertEqual(run["query_count"], 2 + 1 + 3)  # ct+dns, one rdap, three internetdb
        attribution.assess_run(store, run_id)
        f = store.finding(run_id, "fd:ip:198.51.100.4")
        hosting = {x.id: x for x in store.assertions(run_id)}["as:ip:198.51.100.4:hosting"]
        self.assertEqual((hosting.assessment, hosting.value), ("supported", "Corp"))
        rd_ids = [e.id for e in store.evidence(run_id) if e.source == "rdap"]
        self.assertIn(rd_ids[0], f.evidence_ids)

    def test_neighbours_never_queried(self):
        w = world(rdap_fallback=lambda q: CORP_RDAP)
        store, run_id = self.run_world("198.51.100.8/30", w)
        queried = set(w["internetdb"].queries() + w["rdap"].queries())
        self.assertEqual(queried, {"198.51.100.8", "198.51.100.9", "198.51.100.10", "198.51.100.11"})


class TestLimits(EngineCase):
    def test_max_hostnames(self):
        names = [f"h{i}.example.com" for i in range(5)]
        w = world(ct={"example.com": {"certificates": [cert("1", names)]}})
        store, run_id = self.run_world("example.com", w, limits={"max_hostnames": 2})
        self.assertEqual(store.asset_count(run_id, "hostname"), 2)
        trunc = store.run(run_id)["truncated"]
        self.assertEqual([(t["limit"], t["omitted"]) for t in trunc], [("max_hostnames", 3)])
        self.assertEqual(len(w["dns"].queries()), 1 + 2)

    def test_max_addresses(self):
        w = world(dns={"example.com": a("example.com", [f"198.51.100.{i}" for i in range(1, 6)])})
        store, run_id = self.run_world("example.com", w, limits={"max_addresses": 3})
        self.assertEqual(store.asset_count(run_id, "ip"), 3)
        self.assertEqual([(t["limit"], t["omitted"]) for t in store.run(run_id)["truncated"]],
                         [("max_addresses", 2)])
        self.assertEqual(len(w["internetdb"].queries()), 3)

    def test_max_queries(self):
        w = world(dns={"example.com": a("example.com", [f"198.51.100.{i}" for i in range(1, 6)])})
        store, run_id = self.run_world("example.com", w, limits={"max_queries": 4})
        run = store.run(run_id)
        self.assertEqual(run["query_count"], 4)
        total_calls = sum(len(c.queries()) for c in w.values())
        self.assertEqual(total_calls, 4)
        self.assertEqual(len(run["truncated"]), 1)
        t = run["truncated"][0]
        self.assertEqual(t["limit"], "max_queries")
        # ct, dns, then 2 of 5 rdap calls fit; 3 rdap + 5 internetdb tasks are skipped
        self.assertEqual(t["omitted"], 8)
        self.assertEqual(store.pending_tasks(run_id, 100), [])
        # resuming a truncated run does nothing more
        self.assertEqual(engine.execute(store, run_id, w, threading.Event()), "done")
        self.assertEqual(sum(len(c.queries()) for c in w.values()), 4)

    def test_max_queries_exact_fit_is_not_truncated(self):
        w = world(dns={"example.com": "no_record"})
        store, run_id = self.run_world("example.com", w, limits={"max_queries": 2})
        self.assertEqual(store.run(run_id)["truncated"], [])

    def test_max_seconds(self):
        w = world(dns={"example.com": a("example.com", ["198.51.100.1"])})
        store, run_id = self.make_run("example.com", {"max_seconds": 1})
        fake = [0.0]
        orig = engine._clock
        engine._clock = lambda: fake[0]
        try:
            def tick(_c, _q):
                fake[0] += 0.6
            for c in w.values():
                c.on_call = tick
            status = engine.execute(store, run_id, w, threading.Event(), workers=1)
        finally:
            engine._clock = orig
        self.assertEqual(status, "done")
        run = store.run(run_id)
        self.assertEqual([t["limit"] for t in run["truncated"]], ["max_seconds"])
        self.assertEqual(run["truncated"][0]["omitted"], 2)  # rdap + internetdb for the ip
        self.assertGreaterEqual(run["elapsed_seconds"], 1.0)

    def test_max_seconds_accumulates_across_resumes(self):
        w = world()
        store, run_id = self.make_run("example.com", {"max_seconds": 5})
        store.add_elapsed(run_id, 10)
        self.assertEqual(engine.execute(store, run_id, w, threading.Event()), "done")
        run = store.run(run_id)
        self.assertEqual([(t["limit"], t["omitted"]) for t in run["truncated"]], [("max_seconds", 2)])
        self.assertEqual(sum(len(c.queries()) for c in w.values()), 0)


def rich_world(on_call=None):
    return world(
        ct={"example.com": {"certificates": [cert(str(i), [f"h{i}.example.com"]) for i in range(12)]}},
        dns={**{f"h{i}.example.com": a(f"h{i}.example.com", [f"198.51.100.{i % 5 + 1}", f"203.0.113.{i % 3}"],
                                       ["x.vendor.test"] if i % 4 == 0 else [])
                for i in range(12)},
             "example.com": a("example.com", ["198.51.100.1"])},
        internetdb={f"198.51.100.{i}": idb(ports=[443], hostnames=[f"r{i}.example.com"]) for i in range(1, 6)},
        rdap_fallback=lambda q: CORP_RDAP if q.startswith("198.") else
        {"handle": "H2", "network_name": "OTHER", "cidrs": ["203.0.113.0/24"], "org_names": ["Other"],
         "entity_handles": [], "country": None, "registration_date": None, "last_changed": None},
        on_call=on_call)


def snapshot_of(store, run_id):
    attribution.assess_run(store, run_id)
    fs, _ = store.findings(run_id, limit=10_000)
    return {
        "assets": [(r["asset"].id, r["seed_id"], r["depth"], r["path_relationship_id"]) for r in store.assets(run_id)],
        "rels": sorted((r.id, r.evidence_ids, r.depth) for r in store.relationships(run_id)),
        "evidence": sorted(e.id for e in store.evidence(run_id)),
        "findings": [(f.id, f.queue, f.role, f.path, f.flags, f.rank, f.evidence_ids) for f in fs],
        "query_count": store.run(run_id)["query_count"],
    }


class TestDeterminismAndResume(EngineCase):
    def baseline(self):
        store, run_id = self.run_world("example.com", rich_world(), batch_size=7, workers=1)
        return snapshot_of(store, run_id)

    def test_shuffled_completion_order(self):
        base = self.baseline()
        rnd = random.Random(7)
        lock = threading.Lock()

        def jitter(_c, _q):
            with lock:
                d = rnd.random() * 0.004
            time.sleep(d)
        for _ in range(2):
            store, run_id = self.run_world("example.com", rich_world(on_call=jitter), batch_size=7, workers=8)
            self.assertEqual(snapshot_of(store, run_id), base)

    def test_stop_mid_batch_then_resume(self):
        base = self.baseline()
        for stop_after in (1, 3, 9, 20):
            stop = threading.Event()
            calls = [0]
            lock = threading.Lock()

            def maybe_stop(_c, _q):
                with lock:
                    calls[0] += 1
                    if calls[0] == stop_after:
                        stop.set()
            w = rich_world(on_call=maybe_stop)
            store, run_id = self.make_run("example.com")
            rounds = 0
            while True:
                status = engine.execute(store, run_id, w, stop, workers=4, batch_size=7)
                rounds += 1
                if status == "done":
                    break
                self.assertEqual(status, "stopped")
                stop.clear()
                calls[0] = -10_000  # do not stop again
            self.assertEqual(rounds, 2)
            self.assertEqual(snapshot_of(store, run_id), base, stop_after)

    def test_stop_before_start_returns_stopped(self):
        store, run_id = self.make_run("example.com")
        stop = threading.Event()
        stop.set()
        w = world()
        self.assertEqual(engine.execute(store, run_id, w, stop), "stopped")
        self.assertTrue(store.has_tasks(run_id))
        self.assertEqual(sum(len(c.queries()) for c in w.values()), 0)


if __name__ == "__main__":
    unittest.main()
