"""Stage 1 acceptance tests, written from docs/RULES.md and docs/ARCHITECTURE.md against the synthetic Example Corp
world (averiguao_core/connectors/fake.py). Public interfaces only; no network."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone

from averiguao_core import attribution, engine, reports, scope
from averiguao_core.connectors.fake import (DEMO_CONFIG, DEMO_EXPECTED, DEMO_INVENTORY_CSV, DEMO_NEVER_QUERIED,
                                            FIXED_CLOCK, LEGACY_CERT_NOT_AFTER, FakeConnector, all_calls,
                                            demo_world)
from tests.fixtures.pipeline import finish_run, prepare_run, run_pipeline

DIMENSIONS = ("ownership", "operational_control", "hosting", "service_association")
QUEUES = ("known", "new", "unexplained", "third_party")
QUEUE_WEIGHT = {"new": 3, "unexplained": 2, "third_party": 1, "known": 0}
CSV_COLUMNS = ["finding_id", "asset_id", "asset_type", "value", "queue", "role", "inventory_match", "match_rule",
               "inventory_entry", "ownership", "ownership_value", "operational_control",
               "operational_control_value", "hosting", "hosting_value", "service_association", "seed_id",
               "seed_path", "evidence_ids", "first_observed", "last_observed", "flags", "ports", "vulns", "rank"]
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
PREFIX_28 = [str(ip) for ip in ipaddress.ip_network("198.51.100.0/28")]
APPROVED_DNS_NAMES = {"example.com", "www.example.com", "staging.example.com", "app.example.com",
                      "mail.example.com", "status.example.com", "cdn.example.com", "legacy.example.com"}

_TMP: list[tempfile.TemporaryDirectory] = []
_DEMO: dict = {}


def tmpdir() -> str:
    d = tempfile.TemporaryDirectory(prefix="averiguao-acc-")
    _TMP.append(d)
    return d.name


def demo_run():
    """(store, run_id, world) for the demo world with the demo inventory, computed once per process."""
    if not _DEMO:
        world = demo_world()
        store, run_id = run_pipeline(world, DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        _DEMO.update(store=store, run_id=run_id, world=world)
    return _DEMO["store"], _DEMO["run_id"], _DEMO["world"]


def findings(store, run_id):
    items, total = store.findings(run_id, limit=100_000)
    assert len(items) == total, (len(items), total)
    return items


def by_asset(store, run_id):
    return {f.asset_id: f for f in findings(store, run_id)}


def assertion_map(store, run_id):
    return {a.id: a for a in store.assertions(run_id)}


def report_bytes(fn, store, run_id) -> bytes:
    return b"".join(fn(store, run_id))


def csv_rows(store, run_id):
    text = report_bytes(reports.csv_report, store, run_id).decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text, newline=""))
    rows = list(reader)
    return rows[0], [dict(zip(rows[0], r)) for r in rows[1:]]


def candidate_ids(store, run_id):
    return {row["asset"].id for row in store.assets(run_id) if row["asset"].type in ("hostname", "ip")}


# =========================================================================== the fake itself (passes without product)

class TestFakeConnector(unittest.TestCase):
    def test_semantics(self):
        hits = []
        c = FakeConnector("internetdb", {"192.0.2.1": {"ports": [1]}, "192.0.2.2": "error",
                                         "192.0.2.3": lambda q: {"ports": [], "hostnames": [q]},
                                         "192.0.2.4": lambda q: 1 / 0},
                          on_call=lambda conn, q: hits.append(q))
        ok = c.fetch("192.0.2.1")
        self.assertEqual((ok.status, ok.data, ok.retrieved_at), ("ok", {"ports": [1]}, FIXED_CLOCK))
        self.assertEqual(ok.source_url, "https://internetdb.shodan.io/192.0.2.1")
        self.assertEqual(len(ok.raw_sha256), 64)
        self.assertEqual(c.fetch("192.0.2.2").status, "error")
        self.assertEqual(c.fetch("192.0.2.3").data["hostnames"], ["192.0.2.3"])
        self.assertEqual(c.fetch("192.0.2.4").status, "error")
        self.assertEqual(c.fetch("192.0.2.9").status, "no_record")
        self.assertEqual(c.queries(), hits)
        self.assertEqual(FakeConnector("ct").fetch("example.com").source_url,
                         "https://crt.sh/?q=%25.example.com&output=json")

    def test_demo_world_follows_contract_schema(self):
        world = demo_world()
        for name, conn in world.items():
            self.assertEqual(conn.name, name)
        ct = world["ct"].fetch("example.com").data
        self.assertEqual([c["id"] for c in ct["certificates"]], sorted(c["id"] for c in ct["certificates"]))
        for c in ct["certificates"]:
            self.assertEqual(c["names"], sorted(set(c["names"])))
        for ip in PREFIX_28 + ["203.0.113.50", "203.0.113.99"]:
            r = world["internetdb"].fetch(ip)
            for key, val in r.data.items():
                self.assertEqual(val, sorted(set(val)), (ip, key))
        for name in APPROVED_DNS_NAMES:
            r = world["dns"].fetch(name)
            if r.status == "ok":
                self.assertEqual(r.data["addresses"], sorted(set(r.data["addresses"])))
        self.assertEqual(world["rdap"].fetch("198.51.100.13").data["org_names"], ["Example Corp"])
        for ip in ("192.0.2.1", "203.0.113.50", "203.0.113.80", "203.0.113.99"):
            ipaddress.ip_address(ip)  # documentation space only

    def test_demo_inputs_are_accepted(self):
        config = scope.parse_run_config(dict(DEMO_CONFIG), allow_documentation_ranges=True)
        self.assertEqual([(s.id, s.type, s.value) for s in config.seeds],
                         [("seed:1", "domain", "example.com"), ("seed:2", "prefix", "198.51.100.0/28")])
        snap = scope.parse_inventory(DEMO_INVENTORY_CSV)
        self.assertEqual([(e.kind, e.value) for e in snap.entries],
                         [("cidr", "198.51.100.0/30"), ("hostname", "www.example.com"), ("cidr", "10.0.0.0/8")])


# =========================================================================== criterion 1: seed lineage and paths

class TestCriterion1SeedPaths(unittest.TestCase):
    def test_every_finding_walks_back_to_an_approved_seed_with_evidence(self):
        store, run_id, _ = demo_run()
        seed_ids = {s["id"] for s in store.run(run_id)["config"]["seeds"]}
        rels = {r.id: r for r in store.relationships(run_id)}
        ev_ids = {e.id for e in store.evidence(run_id)}
        fs = findings(store, run_id)
        self.assertTrue(fs)
        for f in fs:
            with self.subTest(finding=f.id):
                self.assertIn(f.seed_id, seed_ids)
                self.assertTrue(f.path, "empty path")
                chain = [rels[rid] for rid in f.path]
                self.assertEqual(chain[0].subject_id, f.seed_id)
                self.assertIn(chain[0].predicate, ("seed_is", "prefix_contains_ip"))
                for prev, nxt in zip(chain, chain[1:]):
                    self.assertEqual(prev.object_id, nxt.subject_id)
                self.assertEqual(chain[-1].object_id, f.asset_id)
                for depth, rel in enumerate(chain):
                    self.assertEqual(rel.seed_id, f.seed_id)
                    self.assertGreaterEqual(len(rel.evidence_ids), 1, rel.id)
                    for eid in rel.evidence_ids:
                        self.assertIn(eid, ev_ids)
                    if rel.predicate not in ("seed_is",):
                        self.assertGreaterEqual(rel.depth, 1)
                for eid in f.evidence_ids:
                    self.assertIn(eid, ev_ids)
                path_evidence = {e for rel in chain for e in rel.evidence_ids}
                self.assertTrue(path_evidence <= set(f.evidence_ids))

    def test_ids_follow_contract(self):
        store, run_id, _ = demo_run()
        for f in findings(store, run_id):
            self.assertEqual(f.id, "fd:" + f.asset_id)
            self.assertEqual(f.asset_id, f"{f.asset_type}:{f.value}")
            self.assertEqual(f.review_state, "unreviewed")


# =========================================================================== criterion 2: separate dimensions

class TestCriterion2Dimensions(unittest.TestCase):
    def test_four_assertions_per_candidate(self):
        store, run_id, _ = demo_run()
        amap = assertion_map(store, run_id)
        for f in findings(store, run_id):
            self.assertEqual(f.assertion_ids, tuple(f"as:{f.asset_id}:{d}" for d in DIMENSIONS))
            for aid, dim in zip(f.assertion_ids, DIMENSIONS):
                self.assertEqual(amap[aid].dimension, dim)
                self.assertEqual(amap[aid].asset_id, f.asset_id)
                self.assertIn(amap[aid].assessment, ("supported", "contradicted", "unresolved"))
                self.assertTrue(amap[aid].rationale)

    def _a(self, asset_id):
        store, run_id, _ = demo_run()
        amap = assertion_map(store, run_id)
        return {d: amap[f"as:{asset_id}:{d}"] for d in DIMENSIONS}

    def test_cloud_ip_dimensions_differ(self):
        a = self._a("ip:203.0.113.50")
        self.assertEqual(a["ownership"].assessment, "contradicted")
        self.assertEqual(a["ownership"].value, "Generic Cloud Hosting LLC")
        self.assertEqual(a["operational_control"].assessment, "unresolved")
        self.assertEqual(a["hosting"].assessment, "supported")
        self.assertEqual(a["hosting"].value, "Generic Cloud Hosting LLC")
        self.assertEqual(a["service_association"].assessment, "supported")

    def test_first_party_ip(self):
        a = self._a("ip:198.51.100.9")
        self.assertEqual((a["ownership"].assessment, a["ownership"].value), ("supported", "Example Corp"))
        self.assertEqual(a["operational_control"].assessment, "unresolved")  # registration never proves control
        self.assertEqual((a["hosting"].assessment, a["hosting"].value), ("supported", "Example Corp"))

    def test_hostname_on_cloud(self):
        a = self._a("hostname:app.example.com")
        self.assertEqual((a["ownership"].assessment, a["ownership"].value), ("supported", "example.com"))
        self.assertIn("ev:seed:1", a["ownership"].supporting_evidence_ids)
        self.assertIn(DEMO_CONFIG["approval_ref"].split()[0], a["ownership"].rationale)
        self.assertEqual(a["operational_control"].assessment, "unresolved")
        self.assertEqual((a["hosting"].assessment, a["hosting"].value), ("supported", "Generic Cloud Hosting LLC"))
        self.assertEqual(a["service_association"].assessment, "supported")

    def test_vendor_cname(self):
        a = self._a("hostname:status.example.com")
        self.assertEqual(a["ownership"].assessment, "supported")
        self.assertEqual((a["operational_control"].assessment, a["operational_control"].value),
                         ("contradicted", "saasvendor.test"))
        self.assertEqual((a["hosting"].assessment, a["hosting"].value), ("supported", "SaaS Vendor Inc"))
        c = self._a("hostname:cdn.example.com")
        self.assertEqual((c["operational_control"].assessment, c["operational_control"].value),
                         ("contradicted", "cdn.test"))
        ip = self._a("ip:203.0.113.80")
        self.assertEqual(ip["ownership"].assessment, "contradicted")
        self.assertEqual(ip["operational_control"].assessment, "contradicted")

    def test_no_org_names_means_ip_ownership_unresolved(self):
        body = dict(DEMO_CONFIG, org_names=[])
        store, run_id = run_pipeline(demo_world(), body, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        amap = assertion_map(store, run_id)
        self.assertEqual(amap["as:ip:198.51.100.9:ownership"].assessment, "unresolved")
        self.assertEqual(amap["as:ip:203.0.113.50:ownership"].assessment, "unresolved")


# =========================================================================== criterion 3: inventory reconciliation

class TestCriterion3Reconciliation(unittest.TestCase):
    def test_every_candidate_reconciled_against_run_snapshot(self):
        store, run_id, _ = demo_run()
        run = store.run(run_id)
        self.assertEqual(run["status"], "complete")
        snap_id = run["inventory_snapshot_id"]
        self.assertTrue(snap_id)
        self.assertEqual(store.snapshot(snap_id).label, "test inventory")
        fs = by_asset(store, run_id)
        self.assertEqual(set(fs), candidate_ids(store, run_id))
        for f in fs.values():
            m = f.inventory_match
            self.assertEqual(m.snapshot_id, snap_id)
            self.assertEqual(m.asset_id, f.asset_id)
            self.assertIn(m.rule, ("exact", "prefix_containment", "domain_hierarchy", "none"))
            self.assertEqual(m.entry_id is None, m.rule == "none")
        snap = store.snapshot(snap_id)
        entry = {e.value: e.id for e in snap.entries}
        www = fs["hostname:www.example.com"].inventory_match
        self.assertEqual((www.rule, www.status, www.entry_id), ("exact", "matched", entry["www.example.com"]))
        ip2 = fs["ip:198.51.100.2"].inventory_match
        self.assertEqual((ip2.rule, ip2.status, ip2.entry_id),
                         ("prefix_containment", "matched", entry["198.51.100.0/30"]))
        self.assertEqual((fs["ip:198.51.100.9"].inventory_match.rule, fs["ip:198.51.100.9"].inventory_match.status),
                         ("none", "unmatched"))

    def test_empty_baseline_created_when_no_inventory(self):
        store, run_id = run_pipeline(demo_world(), DEMO_CONFIG, None, tmpdir=tmpdir())
        run = store.run(run_id)
        self.assertEqual(run["status"], "complete")
        self.assertIn("empty_inventory", run["flags"])
        snap = store.snapshot(run["inventory_snapshot_id"])
        self.assertEqual((snap.label, snap.entries), ("empty baseline", ()))
        for f in findings(store, run_id):
            self.assertEqual((f.inventory_match.rule, f.inventory_match.status), ("none", "unmatched"))
            self.assertNotEqual(f.queue, "known")

    def test_prefix_containment_off_is_indeterminate(self):
        store, run_id = run_pipeline(demo_world(), DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir(),
                                     match_rules={"prefix_containment": False})
        f = by_asset(store, run_id)["ip:198.51.100.2"]
        self.assertEqual((f.inventory_match.rule, f.inventory_match.status), ("prefix_containment", "indeterminate"))
        self.assertEqual(f.queue, "unexplained")
        self.assertIn("inventory_match_indeterminate", f.flags)

    def test_domain_tree_respects_domain_hierarchy_rule(self):
        inv = "value,label\n*.example.com,all corporate names\n"
        store, run_id = run_pipeline(demo_world(), DEMO_CONFIG, inv, tmpdir=tmpdir())
        f = by_asset(store, run_id)["hostname:staging.example.com"]
        self.assertEqual((f.inventory_match.rule, f.inventory_match.status), ("domain_hierarchy", "indeterminate"))
        self.assertEqual(f.queue, "unexplained")
        self.assertIn("inventory_match_indeterminate", f.flags)
        store2, run2 = run_pipeline(demo_world(), DEMO_CONFIG, inv, tmpdir=tmpdir(),
                                    match_rules={"domain_hierarchy": True})
        f2 = by_asset(store2, run2)["hostname:status.example.com"]
        self.assertEqual((f2.inventory_match.status, f2.queue), ("matched", "known"))

    def test_re_reconcile_against_newer_snapshot(self):
        world = demo_world()
        store, run_id = run_pipeline(world, DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        before_calls = len(all_calls(world))
        old_snap = store.run(run_id)["inventory_snapshot_id"]
        self.assertEqual(by_asset(store, run_id)["ip:198.51.100.9"].queue, "new")
        store.save_snapshot(scope.parse_inventory(DEMO_INVENTORY_CSV + "198.51.100.9,staging server\n",
                                                  label="second import"))
        attribution.assess_run(store, run_id)
        run = store.run(run_id)
        self.assertNotEqual(run["inventory_snapshot_id"], old_snap)
        f = by_asset(store, run_id)["ip:198.51.100.9"]
        self.assertEqual((f.queue, f.inventory_match.rule, f.inventory_match.status), ("known", "exact", "matched"))
        self.assertEqual(f.inventory_match.snapshot_id, run["inventory_snapshot_id"])
        self.assertEqual(len(all_calls(world)), before_calls, "re-reconciling must not query sources")
        self.assertIsNotNone(store.snapshot(old_snap), "snapshots are never deleted")


# =========================================================================== criterion 4: boundaries and caps

class TestCriterion4Boundaries(unittest.TestCase):
    def test_out_of_scope_counted(self):
        store, run_id, _ = demo_run()
        oos = store.run(run_id)["out_of_scope"]
        self.assertGreaterEqual(oos.get("ct_name_outside_approved_domains", 0), 2, oos)

    def test_depth_limit(self):
        world = demo_world()
        store, run_id = run_pipeline(world, DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir(),
                                     limits={"max_depth": 1})
        run = store.run(run_id)
        self.assertGreater(run["out_of_scope"].get("depth_limit", 0), 0)
        ids = candidate_ids(store, run_id)
        self.assertIn("hostname:staging.example.com", ids)
        for ip in ("ip:203.0.113.50", "ip:203.0.113.80", "ip:203.0.113.99"):
            self.assertNotIn(ip, ids)
        asked = {q for _, q in all_calls(world)}
        self.assertFalse(asked & {"203.0.113.50", "203.0.113.80", "203.0.113.99"})
        self.assertIn("ip:198.51.100.2", ids)  # apex example.com -> .2 is depth 1

    def test_truncation_max_hostnames(self):
        store, run_id = run_pipeline(demo_world(), DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir(),
                                     limits={"max_hostnames": 2})
        run = store.run(run_id)
        self.assertEqual(run["status"], "complete")
        self.assertTrue(run["truncated"])
        t = {x["limit"]: x for x in run["truncated"]}
        self.assertIn("max_hostnames", t)
        self.assertGreaterEqual(t["max_hostnames"]["omitted"], 1)
        self.assertLessEqual(store.asset_count(run_id, "hostname"), 2)
        fs = findings(store, run_id)
        self.assertTrue(fs)
        for f in fs:
            self.assertIn("truncated_run", f.flags)
        md = report_bytes(reports.markdown_report, store, run_id).decode("utf-8")
        self.assertIn("truncat", md.lower())
        js = json.loads(report_bytes(reports.json_report, store, run_id))
        self.assertTrue(js["run"]["truncated"])

    def test_truncation_max_queries(self):
        world = demo_world()
        store, run_id = run_pipeline(world, DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir(),
                                     limits={"max_queries": 5})
        run = store.run(run_id)
        self.assertEqual(run["status"], "complete")
        self.assertIn("max_queries", {x["limit"] for x in run["truncated"]})
        self.assertLessEqual(len(all_calls(world)), 5)
        self.assertLessEqual(run["query_count"], 5)

    def test_untruncated_run_has_no_truncation(self):
        store, run_id, _ = demo_run()
        self.assertEqual(store.run(run_id)["truncated"], [])
        for f in findings(store, run_id):
            self.assertNotIn("truncated_run", f.flags)


# =========================================================================== criterion 5: time and validity

class TestCriterion5Time(unittest.TestCase):
    def test_observed_at_and_validity_kept_apart(self):
        store, run_id, _ = demo_run()
        evs = store.evidence(run_id)
        sources = {e.source for e in evs}
        self.assertTrue({"ct", "dns", "rdap", "internetdb", "scope"} <= sources, sources)
        for e in evs:
            if e.source == "scope":
                continue
            self.assertEqual(e.observed_at, FIXED_CLOCK, e.id)
            if e.source in ("rdap", "internetdb"):
                self.assertIsNone(e.valid_from, e.id)  # source reports no validity: unknown, not retrieval time
                self.assertIsNone(e.valid_to, e.id)
        ct = [e for e in evs if e.source == "ct"]
        self.assertTrue(ct)
        for e in ct:
            self.assertIsNotNone(e.valid_from)
            self.assertIsNotNone(e.valid_to)
            self.assertNotEqual(e.valid_from, e.observed_at)

    def test_stale_certificate(self):
        store, run_id, _ = demo_run()
        fs = by_asset(store, run_id)
        legacy = fs["hostname:legacy.example.com"]
        self.assertIn("stale_evidence", legacy.flags)
        self.assertIn("no_resolution", legacy.flags)
        evs = {e.id: e for e in store.evidence(run_id)}
        legacy_ct = [evs[i] for i in legacy.evidence_ids if evs[i].source == "ct"]
        self.assertTrue(legacy_ct)
        self.assertIn(LEGACY_CERT_NOT_AFTER, {e.valid_to for e in legacy_ct})
        for name in ("www.example.com", "staging.example.com", "app.example.com"):
            self.assertNotIn("stale_evidence", fs["hostname:" + name].flags)
            self.assertNotIn("no_resolution", fs["hostname:" + name].flags)

    def test_conflicting_hosting_is_kept(self):
        store, run_id, _ = demo_run()
        f = by_asset(store, run_id)["hostname:mail.example.com"]
        self.assertIn("conflict", f.flags)
        a = assertion_map(store, run_id)["as:hostname:mail.example.com:hosting"]
        self.assertEqual(a.assessment, "unresolved")
        evs = {e.id: e for e in store.evidence(run_id)}
        cited = set(a.supporting_evidence_ids) | set(a.contradicting_evidence_ids)
        rdap_cited = {i for i in cited if evs[i].source == "rdap"}
        self.assertGreaterEqual(len(rdap_cited), 2, "both providers' evidence must stay visible")

    def test_observation_range(self):
        store, run_id, _ = demo_run()
        for f in findings(store, run_id):
            self.assertIsNotNone(f.first_observed, f.id)
            self.assertIsNotNone(f.last_observed, f.id)
            self.assertLessEqual(f.first_observed, f.last_observed)


# =========================================================================== criterion 6: reports agree

class TestCriterion6Reports(unittest.TestCase):
    def test_json_csv_markdown_agree(self):
        store, run_id, _ = demo_run()
        fs = findings(store, run_id)
        expected = {f.id: f.queue for f in fs}
        js = json.loads(report_bytes(reports.json_report, store, run_id))
        self.assertTrue({"run", "seeds", "assets", "evidence", "relationships", "assertions", "inventory_matches",
                         "findings", "coverage"} <= set(js))
        self.assertEqual({f["id"]: f["queue"] for f in js["findings"]}, expected)
        for key in ("id", "status", "config", "inventory_snapshot", "truncated", "out_of_scope", "source_failures",
                    "query_count", "coverage_summary"):
            self.assertIn(key, js["run"])
        self.assertEqual(js["run"]["inventory_snapshot"]["entry_count"], 3)
        self.assertEqual({a["id"] for a in js["assertions"]}, {a.id for a in store.assertions(run_id)})
        header, rows = csv_rows(store, run_id)
        self.assertEqual(header, CSV_COLUMNS)
        self.assertEqual({r["finding_id"]: r["queue"] for r in rows}, expected)
        amap = assertion_map(store, run_id)
        for r in rows:
            for d in DIMENSIONS:
                self.assertEqual(r[d], amap[f"as:{r['asset_id']}:{d}"].assessment)
        md = report_bytes(reports.markdown_report, store, run_id).decode("utf-8").replace("\\", "")
        for f in fs:
            if f.queue != "known":  # Markdown lists new/unexplained/third-party; known only as a count
                self.assertIn(f.id, md)
        self.assertIn(DEMO_CONFIG["approval_ref"].split()[0], md)

    def test_source_failures_reported(self):
        store, run_id, _ = demo_run()
        run = store.run(run_id)
        self.assertGreaterEqual(run["source_failures"].get("internetdb", 0), 1)
        js = json.loads(report_bytes(reports.json_report, store, run_id))
        self.assertGreaterEqual(js["run"]["source_failures"].get("internetdb", 0), 1)
        md = report_bytes(reports.markdown_report, store, run_id).decode("utf-8").replace("\\", "").lower()
        self.assertIn("internetdb", md)

    def test_coverage_lists_every_prefix_address(self):
        store, run_id, _ = demo_run()
        cov = [c for c in store.coverage(run_id) if c["source"] == "internetdb"]
        status = {c["ip"]: c["status"] for c in cov}
        self.assertTrue(set(PREFIX_28) <= set(status), set(PREFIX_28) - set(status))
        self.assertEqual(status["198.51.100.11"], "error")
        self.assertEqual(status["198.51.100.0"], "no_record")
        self.assertEqual(status["198.51.100.5"], "ok")
        ips = [ipaddress.ip_address(c["ip"]) for c in store.coverage(run_id)]
        self.assertEqual(ips, sorted(ips))

    def test_csv_formula_injection_neutralised(self):
        evil_org = '=HYPERLINK("https://evil.test","click")'
        world = demo_world(overrides={
            "rdap": {"203.0.113.50": {"handle": "NET-EVIL", "network_name": "@EVIL", "cidrs": ["203.0.113.0/26"],
                                      "org_names": [evil_org], "entity_handles": [], "country": None,
                                      "registration_date": None, "last_changed": None}},
            "internetdb": {"198.51.100.9": {"ports": [22], "hostnames": [], "cpes": [], "tags": [],
                                            "vulns": ["+cmd|' /C calc'!A0", "CVE-2023-48795"]}},
        })
        store, run_id = run_pipeline(world, DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        _, rows = csv_rows(store, run_id)
        for r in rows:
            for col, cell in r.items():
                self.assertFalse(cell.startswith(DANGEROUS_PREFIXES), (r["finding_id"], col, cell))
        row = {r["asset_id"]: r for r in rows}
        self.assertEqual(row["ip:203.0.113.50"]["hosting_value"], "'" + evil_org)
        self.assertEqual(row["ip:203.0.113.50"]["ownership_value"], "'" + evil_org)
        self.assertTrue(row["ip:198.51.100.9"]["vulns"].startswith("'+cmd"))

    def test_safe_cell(self):
        for raw in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(reports.safe_cell(raw), "'" + raw)
        self.assertEqual(reports.safe_cell("www.example.com"), "www.example.com")


# =========================================================================== criterion 7: review set

class TestCriterion7ReviewSet(unittest.TestCase):
    def test_all_four_queues_populated(self):
        store, run_id, _ = demo_run()
        queues = {f.queue for f in findings(store, run_id)}
        self.assertEqual(queues, set(QUEUES))
        counts = store.run(run_id)["counts"]
        fs = findings(store, run_id)
        for q in QUEUES:
            self.assertEqual(counts["queue_" + q], sum(1 for f in fs if f.queue == q))


# =========================================================================== scope boundary traps

class TestScopeBoundary(unittest.TestCase):
    def test_no_out_of_scope_name_is_queried_or_recorded(self):
        store, run_id, world = demo_run()
        asked = all_calls(world)
        asked_values = {q for _, q in asked}
        for trap in DEMO_NEVER_QUERIED:
            self.assertNotIn(trap, asked_values)
        ids = {row["asset"].id for row in store.assets(run_id)}
        for trap in ("shop.other-customer.test", "example.com.evil.test", "tenant-a.unrelated.test",
                     "edge.cdn.test", "www.another-brand.test", "example-corp.statuspage.saasvendor.test"):
            self.assertFalse([i for i in ids if i.endswith(":" + trap)], trap)

    def test_query_sets(self):
        store, run_id, world = demo_run()
        self.assertEqual(set(world["ct"].queries()), {"example.com"})
        self.assertEqual(set(world["dns"].queries()), APPROVED_DNS_NAMES)
        reached_ips = {i.split(":", 1)[1] for i in candidate_ids(store, run_id) if i.startswith("ip:")}
        allowed_ips = set(PREFIX_28) | reached_ips
        for src in ("rdap", "internetdb"):
            self.assertTrue(set(world[src].queries()) <= allowed_ips, (src, set(world[src].queries()) - allowed_ips))
        self.assertTrue(set(PREFIX_28) <= set(world["internetdb"].queries()))
        # RDAP is cached by network: the Example Corp /24 is fetched once for this run.
        self.assertEqual(sum(1 for q in world["rdap"].queries() if q.startswith("198.51.100.")), 1)

    def test_wildcard_reduces_to_seed(self):
        store, run_id, _ = demo_run()
        ids = {row["asset"].id for row in store.assets(run_id)}
        self.assertNotIn("hostname:example.com", ids)
        self.assertFalse([i for i in ids if "*" in i])
        self.assertIn("domain:example.com", ids)
        self.assertNotIn("fd:domain:example.com", {f.id for f in findings(store, run_id)})

    def test_internetdb_hostname_is_recorded_not_resolved(self):
        store, run_id, world = demo_run()
        rels = store.relationships(run_id)
        self.assertTrue([r for r in rels if r.predicate == "ip_reports_hostname"
                         and r.subject_id == "ip:198.51.100.5" and r.object_id == "hostname:vpn.example.com"])
        self.assertNotIn("vpn.example.com", world["dns"].queries())

    def test_prefix_members_without_data_are_not_assets(self):
        store, run_id, _ = demo_run()
        ids = candidate_ids(store, run_id)
        for ip in ("198.51.100.0", "198.51.100.8", "198.51.100.11", "198.51.100.15"):
            self.assertNotIn("ip:" + ip, ids)

    def test_ip_seed_does_not_expand(self):
        world = demo_world()
        body = {"seeds": "203.0.113.50", "approval_ref": "TEST-IP-1", "org_names": ["Example Corp"]}
        store, run_id = run_pipeline(world, body, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        self.assertEqual(world["dns"].queries(), [])
        self.assertEqual(world["ct"].queries(), [])
        self.assertEqual(set(world["rdap"].queries()) | set(world["internetdb"].queries()), {"203.0.113.50"})
        fs = by_asset(store, run_id)
        self.assertEqual(set(fs), {"ip:203.0.113.50"})
        self.assertEqual(fs["ip:203.0.113.50"].queue, "unexplained")


# =========================================================================== queues of the demo world

class TestQueues(unittest.TestCase):
    def test_exact_candidate_set_and_queues(self):
        store, run_id, _ = demo_run()
        got = {f.asset_id: f.queue for f in findings(store, run_id)}
        self.assertEqual(set(got), set(DEMO_EXPECTED))
        for asset, (queue, why) in DEMO_EXPECTED.items():
            with self.subTest(asset=asset):
                self.assertEqual(got[asset], queue, why)

    def test_roles(self):
        store, run_id, _ = demo_run()
        fs = by_asset(store, run_id)
        expected = {"hostname:staging.example.com": "first_party", "ip:198.51.100.9": "first_party",
                    "ip:198.51.100.5": "first_party", "ip:203.0.113.50": "unresolved",
                    "hostname:status.example.com": "third_party", "ip:203.0.113.80": "third_party",
                    "hostname:cdn.example.com": "third_party", "ip:203.0.113.99": "third_party"}
        for asset, role in expected.items():
            self.assertEqual(fs[asset].role, role, asset)

    def test_flags(self):
        store, run_id, _ = demo_run()
        fs = by_asset(store, run_id)
        for f in fs.values():
            self.assertEqual(list(f.flags), sorted(set(f.flags)))
        self.assertIn("potential_vulns", fs["ip:198.51.100.9"].flags)
        self.assertNotIn("potential_vulns", fs["ip:198.51.100.2"].flags)
        self.assertNotIn("conflict", fs["ip:203.0.113.50"].flags)

    def test_rank_order(self):
        store, run_id, _ = demo_run()
        fs = findings(store, run_id)
        self.assertEqual([f.id for f in fs], [f.id for f in sorted(fs, key=lambda f: (-f.rank, f.value))])
        for f in fs:
            w = QUEUE_WEIGHT[f.queue]
            self.assertGreaterEqual(f.rank, w - 0.3 - 1e-9, f.id)
            self.assertLess(f.rank, w + 1, f.id)
        fsa = by_asset(store, run_id)
        self.assertGreater(fsa["ip:198.51.100.9"].rank, fsa["ip:198.51.100.5"].rank)  # vulns + ports

    def test_filters(self):
        store, run_id, _ = demo_run()
        items, total = store.findings(run_id, queue="third_party")
        self.assertEqual(total, 4)
        self.assertEqual({f.queue for f in items}, {"third_party"})
        items, total = store.findings(run_id, flag="stale_evidence")
        self.assertIn("fd:hostname:legacy.example.com", {f.id for f in items})


# =========================================================================== pause and resume

class TestResume(unittest.TestCase):
    def test_stop_and_resume_matches_uninterrupted_run(self):
        stop = threading.Event()
        lock = threading.Lock()
        counter = [0]

        def hook(conn, query):
            with lock:
                counter[0] += 1
                if counter[0] >= 3:
                    stop.set()

        world = demo_world()
        for conn in world.values():
            conn.on_call = hook
        store, run_id = prepare_run(DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=tmpdir())
        store.set_status(run_id, "running")
        self.assertEqual(engine.execute(store, run_id, world, stop, workers=4, batch_size=16), "stopped")
        self.assertTrue(store.has_tasks(run_id), "stop must leave work pending")
        for conn in world.values():
            conn.on_call = None
        self.assertEqual(engine.execute(store, run_id, world, threading.Event(), workers=4, batch_size=16), "done")
        finish_run(store, run_id)

        ref_store, ref_run, _ = demo_run()

        def summary(s, r):
            return {f.id: (f.queue, f.role, f.flags, round(f.rank, 6), f.inventory_match.status)
                    for f in findings(s, r)}

        self.assertEqual(summary(store, run_id), summary(ref_store, ref_run))
        self.assertEqual({a.id: a.assessment for a in store.assertions(run_id)},
                         {a.id: a.assessment for a in ref_store.assertions(ref_run)})


if __name__ == "__main__":
    unittest.main()
