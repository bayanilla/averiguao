"""Attribution, reconciliation, flags and rank tests (docs/RULES.md sections 3-6). No network."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from averiguao_core import attribution, engine, scope
from averiguao_core.attribution import assess, org_matches, reconcile, registrable_base
from averiguao_core.connectors.fake import FakeConnector
from averiguao_core.contracts import Asset, Evidence, InventoryEntry, InventorySnapshot, Relationship
from averiguao_core.store import Store

T = "2026-10-01T00:00:00+00:00"
DONE = "2026-10-02T00:00:00+00:00"
CORP = {"handle": "NET-CORP", "network_name": "CORP-NET", "cidrs": ["198.51.100.0/24"], "org_names": ["Example Corp"],
        "entity_handles": ["EXCO-1"]}
CLOUD = {"handle": "NET-CLOUD", "network_name": "CLOUD-NET", "cidrs": ["203.0.113.0/24"],
         "org_names": ["Generic Cloud LLC"], "entity_handles": []}


def config(seeds="example.com\n198.51.100.0/28", org_names=("Example Corp",), match_rules=None):
    body = {"seeds": seeds, "approval_ref": "TICKET-9", "org_names": list(org_names)}
    if match_rules:
        body["match_rules"] = match_rules
    return scope.parse_run_config(body, allow_documentation_ranges=True)


def snap(*entries):
    return InventorySnapshot(id="snap:test", as_of=T, imported_at=T, label="t",
                             entries=tuple(InventoryEntry(id=f"inv:{i + 1}", kind=k, value=v, label="")
                                           for i, (k, v) in enumerate(entries)))


class World:
    """Hand-built discovery records for assess()."""

    def __init__(self):
        self.assets: list[dict] = []
        self.rels: list[Relationship] = []
        self.evs: list[Evidence] = [
            Evidence("ev:seed:1", "scope", "example.com", "", None, T, None, None, "seed:1",
                     {"approval_ref": "TICKET-9", "scope_version": "1", "seed_type": "domain"})]
        self._n = 0
        self.asset("domain", "example.com", "rel:seed")
        self.rels.append(Relationship("rel:seed", "seed:1", "seed_is", "domain:example.com", ("ev:seed:1",),
                                      "seed:1", 0))

    def ev(self, source, query, data, valid_to=None, observed=T):
        self._n += 1
        e = Evidence(f"ev:{self._n:04d}", source, query, "", None, observed, None, valid_to, None, data)
        self.evs.append(e)
        return e.id

    def asset(self, type_, value, rel_id, depth=1):
        if not any(r["asset"].id == f"{type_}:{value}" for r in self.assets):
            self.assets.append({"asset": Asset(f"{type_}:{value}", type_, value), "seed_id": "seed:1",
                                "depth": depth, "path_relationship_id": rel_id})

    def rel(self, subject, predicate, obj, ev_ids):
        rid = f"rel:{len(self.rels)}"
        self.rels.append(Relationship(rid, subject, predicate, obj, tuple(ev_ids), "seed:1", 1))
        return rid

    def hostname(self, name, *, addresses=None, cnames=(), not_after="2027-01-01T00:00:00+00:00"):
        ct = self.ev("ct", "example.com", {"id": name, "names": [name]}, valid_to=not_after)
        rid = self.rel("domain:example.com", "certificate_mentions_hostname", f"hostname:{name}", [ct])
        self.asset("hostname", name, rid)
        if addresses is None:
            self.ev("dns", name, {"status": "no_record"})
            return
        dns = self.ev("dns", name, {"name": name, "cnames": list(cnames), "addresses": addresses, "ttl": 60})
        for ip in addresses:
            r = self.rel(f"hostname:{name}", "hostname_resolves_to_ip", f"ip:{ip}", [dns])
            self.asset("ip", ip, r, 2)
        return dns

    def rdap(self, ip, data):
        return self.ev("rdap", ip, dict(data))

    def idb(self, ip, ports=(), vulns=(), hostnames=()):
        return self.ev("internetdb", ip, {"ports": list(ports), "vulns": list(vulns), "hostnames": list(hostnames),
                                          "cpes": [], "tags": []})

    def assess(self, cfg=None, snapshot=None, truncated=False, source_errors=None):
        res = assess(cfg or config(), self.assets, self.rels, self.evs, snapshot or snap(), completed_at=DONE,
                     truncated=truncated, source_errors=source_errors)
        self.res = res
        self.f = {f.asset_id: f for f in res.findings}
        self.a = {x.id: x for x in res.assertions}
        return res

    def A(self, aid, dim):
        return self.a[f"as:{aid}:{dim}"]


class TestHelpers(unittest.TestCase):
    def test_registrable_base(self):
        self.assertEqual(registrable_base("edge.cdn.test"), "cdn.test")
        self.assertEqual(registrable_base("a.b.vendor.co.uk"), "vendor.co.uk")
        self.assertEqual(registrable_base("x.shop.com.au"), "shop.com.au")
        self.assertEqual(registrable_base("vendor.test"), "vendor.test")

    def test_org_match(self):
        self.assertEqual(org_matches(["example corp"], {"org_names": ["EXAMPLE   Corp"]}), "example corp")
        self.assertEqual(org_matches(["Example"], {"network_name": "EXAMPLE-NET"}), "Example")
        self.assertEqual(org_matches(["EXCO-1"], {"entity_handles": ["EXCO-1"]}), "EXCO-1")
        self.assertEqual(org_matches(["NET-CORP"], {"handle": "NET-CORP"}), "NET-CORP")
        self.assertIsNone(org_matches(["Example"], {"org_names": ["Examples Inc"]}))  # not a whole word
        self.assertIsNone(org_matches(["Acme"], {"org_names": ["Example Corp"], "network_name": "X"}))


class TestHostnameAssertions(unittest.TestCase):
    def test_in_scope_resolving(self):
        w = World()
        w.hostname("www.example.com", addresses=["198.51.100.2"])
        w.rdap("198.51.100.2", CORP)
        w.assess()
        own = w.A("hostname:www.example.com", "ownership")
        self.assertEqual((own.assessment, own.value), ("supported", "example.com"))
        self.assertEqual(own.supporting_evidence_ids, ("ev:seed:1",))
        self.assertIn("TICKET-9", own.rationale)
        self.assertEqual(w.A("hostname:www.example.com", "operational_control").assessment, "unresolved")
        host = w.A("hostname:www.example.com", "hosting")
        self.assertEqual((host.assessment, host.value), ("supported", "Example Corp"))
        self.assertEqual(w.A("hostname:www.example.com", "service_association").assessment, "supported")
        f = w.f["hostname:www.example.com"]
        self.assertEqual((f.role, f.queue), ("first_party", "new"))
        self.assertEqual(f.assertion_ids, tuple(f"as:hostname:www.example.com:{d}" for d in attribution.DIMENSIONS))

    def test_external_cname_third_party(self):
        w = World()
        w.hostname("status.example.com", addresses=["203.0.113.80"], cnames=["corp.status.vendor.co.uk"])
        w.rdap("203.0.113.80", CLOUD)
        w.assess()
        oc = w.A("hostname:status.example.com", "operational_control")
        self.assertEqual((oc.assessment, oc.value), ("contradicted", "vendor.co.uk"))
        self.assertTrue(oc.contradicting_evidence_ids)
        self.assertEqual(w.f["hostname:status.example.com"].queue, "third_party")
        ipoc = w.A("ip:203.0.113.80", "operational_control")
        self.assertEqual((ipoc.assessment, ipoc.value), ("contradicted", "vendor.co.uk"))
        self.assertEqual(w.f["ip:203.0.113.80"].queue, "third_party")

    def test_internal_cname_not_contradicted(self):
        w = World()
        w.hostname("a.example.com", addresses=["198.51.100.2"], cnames=["lb.example.com"])
        w.assess()
        self.assertEqual(w.A("hostname:a.example.com", "operational_control").assessment, "unresolved")

    def test_latest_ok_dns_decides_control(self):
        w = World()
        w.hostname("a.example.com", addresses=["198.51.100.2"], cnames=["x.vendor.test"])
        w.ev("dns", "a.example.com", {"name": "a.example.com", "cnames": [], "addresses": ["198.51.100.2"]},
             observed="2026-10-01T05:00:00+00:00")
        w.ev("dns", "a.example.com", {"status": "error", "error": "x"}, observed="2026-10-01T06:00:00+00:00")
        w.assess()
        self.assertEqual(w.A("hostname:a.example.com", "operational_control").assessment, "unresolved")

    def test_hosting_conflict(self):
        w = World()
        w.hostname("mail.example.com", addresses=["198.51.100.3", "203.0.113.50"])
        w.rdap("198.51.100.3", CORP)
        w.rdap("203.0.113.50", CLOUD)
        w.assess()
        h = w.A("hostname:mail.example.com", "hosting")
        self.assertEqual(h.assessment, "unresolved")
        self.assertTrue(h.supporting_evidence_ids and h.contradicting_evidence_ids)
        self.assertIn("conflict", w.f["hostname:mail.example.com"].flags)

    def test_no_resolution_and_stale(self):
        w = World()
        w.hostname("legacy.example.com", addresses=None, not_after="2019-06-01T00:00:00+00:00")
        w.assess()
        f = w.f["hostname:legacy.example.com"]
        self.assertEqual(w.A("hostname:legacy.example.com", "hosting").assessment, "unresolved")
        self.assertIn("no_resolution", f.flags)
        self.assertIn("stale_evidence", f.flags)
        # stale: -0.3; distinct ok sources = ct only
        self.assertAlmostEqual(f.rank, 3 + 0.1 - 0.3)

    def test_expired_cert_but_resolving_not_stale(self):
        w = World()
        w.hostname("old.example.com", addresses=["198.51.100.4"], not_after="2019-06-01T00:00:00+00:00")
        w.assess()
        self.assertNotIn("stale_evidence", w.f["hostname:old.example.com"].flags)

    def test_internetdb_only_hostname_has_no_no_resolution(self):
        w = World()
        w.hostname("x.example.com", addresses=["198.51.100.5"])
        e = w.idb("198.51.100.5", hostnames=["vpn.example.com"])
        rid = w.rel("ip:198.51.100.5", "ip_reports_hostname", "hostname:vpn.example.com", [e])
        w.asset("hostname", "vpn.example.com", rid)
        w.assess()
        f = w.f["hostname:vpn.example.com"]
        self.assertNotIn("no_resolution", f.flags)
        self.assertEqual(f.path, ("rel:seed", "rel:1", "rel:2", rid))
        sa = w.A("ip:198.51.100.5", "service_association")
        self.assertEqual(sa.assessment, "supported")
        self.assertIn(e, sa.supporting_evidence_ids)


class TestIpAssertions(unittest.TestCase):
    def ip_world(self, rdap=None):
        w = World()
        w.hostname("h.example.com", addresses=["198.51.100.9"])
        if rdap is not None:
            w.rdap("198.51.100.9", rdap)
        return w

    def test_ownership_supported(self):
        w = self.ip_world(CORP)
        w.assess()
        o = w.A("ip:198.51.100.9", "ownership")
        self.assertEqual((o.assessment, o.value), ("supported", "Example Corp"))
        self.assertEqual(w.A("ip:198.51.100.9", "hosting").value, "Example Corp")
        self.assertEqual(w.f["ip:198.51.100.9"].role, "first_party")

    def test_ownership_contradicted(self):
        w = self.ip_world(CLOUD)
        w.assess()
        o = w.A("ip:198.51.100.9", "ownership")
        self.assertEqual((o.assessment, o.value), ("contradicted", "Generic Cloud LLC"))
        self.assertTrue(o.contradicting_evidence_ids)
        f = w.f["ip:198.51.100.9"]
        self.assertEqual((f.role, f.queue), ("unresolved", "unexplained"))

    def test_ownership_network_name_fallback(self):
        w = self.ip_world({"handle": "H", "network_name": "SOME-NET", "cidrs": ["198.51.100.0/24"],
                           "org_names": [], "entity_handles": []})
        w.assess()
        self.assertEqual(w.A("ip:198.51.100.9", "ownership").value, "SOME-NET")
        self.assertEqual(w.A("ip:198.51.100.9", "hosting").value, "SOME-NET")

    def test_ownership_unresolved_cases(self):
        w = self.ip_world(None)
        w.assess()
        self.assertEqual(w.A("ip:198.51.100.9", "ownership").assessment, "unresolved")
        self.assertEqual(w.A("ip:198.51.100.9", "hosting").assessment, "unresolved")
        w = self.ip_world(CORP)
        w.assess(cfg=config(org_names=()))
        self.assertEqual(w.A("ip:198.51.100.9", "ownership").assessment, "unresolved")
        w = self.ip_world(None)
        err = w.ev("rdap", "198.51.100.9", {"status": "error", "error": "timeout"})
        w.assess(source_errors={"ip:198.51.100.9": [err]})
        self.assertEqual(w.A("ip:198.51.100.9", "ownership").assessment, "unresolved")
        f = w.f["ip:198.51.100.9"]
        self.assertIn("source_error", f.flags)
        self.assertIn(err, f.evidence_ids)

    def test_rdap_reused_by_containment(self):
        w = self.ip_world(None)
        w.rdap("198.51.100.0", CORP)  # prefix network lookup
        w.assess()
        self.assertEqual(w.A("ip:198.51.100.9", "ownership").assessment, "supported")

    def test_control_mixed_paths_conflict(self):
        w = World()
        w.hostname("a.example.com", addresses=["203.0.113.5"], cnames=["x.cdn.test"])
        w.hostname("b.example.com", addresses=["203.0.113.5"])
        w.assess()
        oc = w.A("ip:203.0.113.5", "operational_control")
        self.assertEqual(oc.assessment, "unresolved")
        self.assertTrue(oc.supporting_evidence_ids and oc.contradicting_evidence_ids)
        self.assertIn("conflict", w.f["ip:203.0.113.5"].flags)

    def test_service_association_unresolved_for_bare_prefix_member(self):
        w = World()
        e = w.idb("198.51.100.6", ports=[443])
        rid = w.rel("seed:2", "prefix_contains_ip", "ip:198.51.100.6", [e])
        w.asset("ip", "198.51.100.6", rid)
        w.assess()
        self.assertEqual(w.A("ip:198.51.100.6", "service_association").assessment, "unresolved")
        self.assertEqual(w.A("ip:198.51.100.6", "operational_control").assessment, "unresolved")

    def test_vulns_ports_rank(self):
        w = self.ip_world(CORP)
        w.idb("198.51.100.9", ports=[22], vulns=["CVE-1"])
        w.assess()
        f = w.f["ip:198.51.100.9"]
        self.assertIn("potential_vulns", f.flags)
        # new 3 + sources {ct, dns, rdap, internetdb} 0.4 + vulns 0.2 + ports 0.1
        self.assertAlmostEqual(f.rank, 3.7)

    def test_truncated_flag_and_sorting(self):
        w = self.ip_world(CLOUD)
        w.assess(truncated=True)
        self.assertTrue(all("truncated_run" in f.flags for f in w.res.findings))
        keys = [(-f.rank, f.value) for f in w.res.findings]
        self.assertEqual(keys, sorted(keys))
        self.assertNotIn("domain:example.com", w.f)
        f = w.f["ip:198.51.100.9"]
        self.assertEqual((f.first_observed, f.last_observed), (T, T))


class TestReconciliation(unittest.TestCase):
    def check(self, a, entries, rules, expect):
        cfg = config(match_rules=rules) if rules else config()
        m = reconcile(a, snap(*entries), cfg.match_rules.prefix_containment, cfg.match_rules.domain_hierarchy)
        self.assertEqual((m.rule, m.status, m.entry_id), expect)

    def test_rules(self):
        ip = Asset("ip:198.51.100.9", "ip", "198.51.100.9")
        host = Asset("hostname:a.b.example.com", "hostname", "a.b.example.com")
        self.check(ip, [("ip", "198.51.100.9")], None, ("exact", "matched", "inv:1"))
        self.check(ip, [("cidr", "198.51.100.9/32")], None, ("exact", "matched", "inv:1"))
        self.check(ip, [("cidr", "198.51.100.0/24"), ("cidr", "198.51.100.8/29")], None,
                   ("prefix_containment", "matched", "inv:2"))
        self.check(ip, [("cidr", "198.51.100.0/24")], {"prefix_containment": False},
                   ("prefix_containment", "indeterminate", "inv:1"))
        self.check(ip, [("cidr", "10.0.0.0/8")], None, ("none", "unmatched", None))
        self.check(host, [("hostname", "a.b.example.com")], None, ("exact", "matched", "inv:1"))
        self.check(host, [("domain_tree", "example.com")], None, ("domain_hierarchy", "indeterminate", "inv:1"))
        self.check(host, [("domain_tree", "example.com"), ("domain_tree", "b.example.com")],
                   {"domain_hierarchy": True}, ("domain_hierarchy", "matched", "inv:2"))
        self.check(host, [("hostname", "b.example.com")], None, ("none", "unmatched", None))

    def test_queues(self):
        w = World()
        w.hostname("known.example.com", addresses=["198.51.100.2"])
        w.hostname("tree.example.com", addresses=None)
        w.hostname("vendor.example.com", addresses=["203.0.113.80"], cnames=["x.vendor.test"])
        w.rdap("198.51.100.2", CORP)
        w.rdap("203.0.113.80", CLOUD)
        w.assess(snapshot=snap(("hostname", "known.example.com"), ("cidr", "198.51.100.0/30"),
                               ("domain_tree", "tree.example.com")))
        q = {aid: f.queue for aid, f in w.f.items()}
        self.assertEqual(q["hostname:known.example.com"], "known")
        self.assertEqual(q["ip:198.51.100.2"], "known")
        self.assertEqual(q["hostname:tree.example.com"], "unexplained")
        self.assertIn("inventory_match_indeterminate", w.f["hostname:tree.example.com"].flags)
        self.assertEqual(q["hostname:vendor.example.com"], "third_party")
        self.assertEqual(q["ip:203.0.113.80"], "third_party")
        self.assertAlmostEqual(w.f["ip:198.51.100.2"].rank, 0.3)  # known: ct, dns, rdap on path/enrichment


class TestAssessRun(unittest.TestCase):
    def test_empty_inventory_baseline_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / "db.sqlite3")
            cfg = config(seeds="example.com")
            run_id = store.create_run(cfg)
            w = {
                "ct": FakeConnector("ct", {"example.com": {"certificates": [
                    {"id": "1", "names": ["www.example.com"], "not_before": None, "not_after": None,
                     "issuer": None}]}}, clock=T),
                "dns": FakeConnector("dns", {"www.example.com": {"name": "www.example.com", "cnames": [],
                                                                 "addresses": ["198.51.100.2"], "ttl": 1}}, clock=T),
                "rdap": FakeConnector("rdap", {"198.51.100.2": "error"}, clock=T),
                "internetdb": FakeConnector("internetdb", {}, clock=T),
            }
            self.assertEqual(engine.execute(store, run_id, w, threading.Event()), "done")
            attribution.assess_run(store, run_id)
            run = store.run(run_id)
            self.assertIn("empty_inventory", run["flags"])
            snapshot = store.current_snapshot()
            self.assertEqual((snapshot.label, snapshot.entries), ("empty baseline", ()))
            self.assertEqual(run["inventory_snapshot_id"], snapshot.id)
            f = store.finding(run_id, "fd:ip:198.51.100.2")
            self.assertIn("source_error", f.flags)
            self.assertEqual(f.queue, "unexplained")
            self.assertEqual(store.finding(run_id, "fd:hostname:www.example.com").queue, "new")


if __name__ == "__main__":
    unittest.main()
