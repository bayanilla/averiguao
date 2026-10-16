import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from averiguao_core.contracts import (Assertion, Asset, Evidence, Finding, InventoryEntry, InventoryMatch,
                                      InventorySnapshot, Relationship, RunConfig, Seed, Truncation)
from averiguao_core.store import Store


def make_config(label="test"):
    return RunConfig(seeds=(Seed("seed:1", "domain", "example.com", "TICKET-1", "1"),
                            Seed("seed:2", "prefix", "198.51.100.0/30", "TICKET-1", "1")),
                     org_names=("Example Corp",), label=label)


def ev(i, source="ct", data=None):
    return Evidence(id=f"ev:{i}", source=source, query=f"q{i}", source_url=f"https://src/{i}", raw_sha256="ab" * 32,
                    observed_at="2026-10-16T00:00:00+00:00", valid_from=None, valid_to="2027-01-01T00:00:00+00:00",
                    source_record_id=f"r{i}", data={"certificates": [{"id": str(i), "names": ["a.example.com"]}]}
                    if data is None else data)


def rel(rid, evidence_ids, obj="hostname:a.example.com"):
    return Relationship(id=rid, subject_id="domain:example.com", predicate="certificate_mentions_hostname",
                        object_id=obj, evidence_ids=tuple(evidence_ids), seed_id="seed:1", depth=1)


def match(asset_id, status="unmatched"):
    return InventoryMatch(asset_id=asset_id, snapshot_id="snap:1", entry_id=None, rule="none", status=status)


def finding(value, queue="new", rank=3.0, flags=(), type_="hostname"):
    aid = f"{type_}:{value}"
    return Finding(id=f"fd:{aid}", asset_id=aid, asset_type=type_, value=value, queue=queue, role="first_party",
                   inventory_match=match(aid), assertion_ids=tuple(f"as:{aid}:{d}" for d in
                                                                   ("ownership", "operational_control", "hosting",
                                                                    "service_association")),
                   seed_id="seed:1", path=("rel:1",), evidence_ids=("ev:1",), first_observed=None,
                   last_observed="2026-10-16T00:00:00+00:00", flags=tuple(sorted(flags)), rank=rank)


def batch(store, run_id, **kw):
    args = dict(done_task_ids=[], evidence=[], assets=[], relationships=[], new_tasks=[], coverage=[], queries=0,
                source_failures={}, out_of_scope={}, truncations=[])
    args.update(kw)
    store.commit_batch(run_id, **args)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "sub" / "db.sqlite3"
        self.store = Store(self.path)
        self.run_id = self.store.create_run(make_config())

    def tearDown(self):
        self.tmp.cleanup()


class SchemaTests(StoreTestCase):
    def test_schema_and_pragmas(self):
        db = sqlite3.connect(self.path)
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ("runs", "tasks", "evidence", "assets", "relationships", "coverage", "assertions",
                     "inventory_matches", "findings", "inventory_snapshots", "inventory_entries", "schema_version"):
            self.assertIn(name, tables)
        self.assertEqual(db.execute("SELECT version FROM schema_version").fetchall(), [(1,)])
        self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        db.close()
        Store(self.path)  # reopening is idempotent
        db = sqlite3.connect(self.path)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0], 1)
        db.close()

    def test_newer_schema_rejected(self):
        db = sqlite3.connect(self.path)
        db.execute("UPDATE schema_version SET version=99")
        db.commit()
        db.close()
        with self.assertRaises(RuntimeError):
            Store(self.path)


class RunTests(StoreTestCase):
    def test_create_and_read_run(self):
        run = self.store.run(self.run_id)
        self.assertEqual(len(self.run_id), 32)
        self.assertEqual(run["status"], "queued")
        self.assertEqual(run["label"], "test")
        self.assertEqual(run["config"], json.loads(json.dumps(make_config().to_dict())))
        self.assertEqual(self.store.run_config(self.run_id), make_config())
        self.assertEqual(run["truncated"], [])
        self.assertEqual(run["out_of_scope"], {})
        self.assertEqual(run["source_failures"], {})
        self.assertEqual(run["query_count"], 0)
        self.assertEqual(run["elapsed_seconds"], 0.0)
        self.assertEqual(run["flags"], [])
        self.assertIsNone(run["started_at"])
        self.assertEqual(set(run["counts"]), {"tasks_pending", "tasks_done", "assets", "findings", "coverage_checked",
                                              "coverage_no_record", "queue_known", "queue_new", "queue_unexplained",
                                              "queue_third_party"})
        self.assertIsNone(self.store.run("missing"))

    def test_runs_newest_first_and_next_queued_oldest(self):
        second = self.store.create_run(make_config("two"))
        third = self.store.create_run(make_config("three"))
        self.assertEqual([r["id"] for r in self.store.runs()], [third, second, self.run_id])
        self.assertEqual(len(self.store.runs(limit=1)), 1)
        self.assertEqual(self.store.next_queued_run(), self.run_id)
        self.store.set_status(self.run_id, "running")
        self.assertEqual(self.store.next_queued_run(), second)

    def test_status_timestamps_and_errors(self):
        self.store.set_status(self.run_id, "running")
        started = self.store.run(self.run_id)["started_at"]
        self.assertIsNotNone(started)
        self.store.set_status(self.run_id, "paused", "oops")
        self.assertEqual(self.store.run(self.run_id)["last_error"], "oops")
        self.store.set_status(self.run_id, "running")
        run = self.store.run(self.run_id)
        self.assertEqual(run["started_at"], started)
        self.assertIsNone(run["last_error"])
        self.assertIsNone(run["finished_at"])
        self.store.set_status(self.run_id, "failed", "Boom: x")
        run = self.store.run(self.run_id)
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(run["last_error"], "Boom: x")
        with self.assertRaises(ValueError):
            self.store.set_status(self.run_id, "bogus")

    def test_flags_dedup_and_elapsed(self):
        self.store.add_run_flag(self.run_id, "empty_inventory")
        self.store.add_run_flag(self.run_id, "empty_inventory")
        self.store.add_run_flag(self.run_id, "other")
        self.store.add_elapsed(self.run_id, 1.5)
        self.store.add_elapsed(self.run_id, 2.25)
        run = self.store.run(self.run_id)
        self.assertEqual(run["flags"], ["empty_inventory", "other"])
        self.assertAlmostEqual(run["elapsed_seconds"], 3.75)


class TaskTests(StoreTestCase):
    def test_add_pending_duplicates_skip(self):
        self.assertFalse(self.store.has_tasks(self.run_id))
        n = self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:1", 0, "domain:example.com"),
                                               ("dns", "example.com", "seed:1", 0, "domain:example.com"),
                                               ("ct", "example.com", "seed:1", 0, "domain:example.com")])
        self.assertEqual(n, 2)
        self.assertEqual(self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:1", 1, None)]), 0)
        # Same (source, query) from another seed is ignored: first seed wins.
        self.assertEqual(self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:2", 1, None)]), 0)
        self.assertEqual(self.store.add_tasks(self.run_id, [("ct", "other.example", "seed:2", 1, None)]), 1)
        self.assertTrue(self.store.has_tasks(self.run_id))
        pending = self.store.pending_tasks(self.run_id, 10)
        self.assertEqual([(t["source"], t["query"], t["seed_id"]) for t in pending],
                         [("ct", "example.com", "seed:1"), ("dns", "example.com", "seed:1"),
                          ("ct", "other.example", "seed:2")])
        self.assertEqual(set(pending[0]), {"id", "source", "query", "seed_id", "depth", "from_asset_id"})
        self.assertEqual(pending[0]["from_asset_id"], "domain:example.com")
        self.assertEqual(len(self.store.pending_tasks(self.run_id, 2)), 2)
        batch(self.store, self.run_id, done_task_ids=[pending[0]["id"]])
        self.assertEqual(self.store.skip_pending_tasks(self.run_id), 2)
        self.assertEqual(self.store.pending_tasks(self.run_id, 10), [])
        counts = self.store.run(self.run_id)["counts"]
        self.assertEqual((counts["tasks_pending"], counts["tasks_done"]), (0, 1))


class BatchTests(StoreTestCase):
    def test_round_trip_and_counters(self):
        self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:1", 0, None)])
        task_id = self.store.pending_tasks(self.run_id, 1)[0]["id"]
        rdap_ok = ev(2, "rdap", {"handle": "NET-1", "cidrs": ["198.51.100.0/24"], "org_names": ["Example"]})
        rdap_err = ev(3, "rdap", {})
        batch(self.store, self.run_id, done_task_ids=[task_id], evidence=[ev(1), rdap_ok, rdap_err],
              assets=[(Asset("hostname:a.example.com", "hostname", "a.example.com"), "seed:1", 1, "rel:1"),
                      (Asset("ip:198.51.100.1", "ip", "198.51.100.1"), "seed:2", 1, "rel:2")],
              relationships=[rel("rel:1", ["ev:1"])],
              new_tasks=[("dns", "a.example.com", "seed:1", 1, "hostname:a.example.com")],
              coverage=[("198.51.100.1", "internetdb", "ok", "t1"), ("198.51.100.2", "internetdb", "no_record", "t1")],
              queries=3, source_failures={"rdap": 1}, out_of_scope={"depth_limit": 2},
              truncations=[Truncation("max_hostnames", 2, "first")])
        batch(self.store, self.run_id, queries=2, source_failures={"rdap": 2, "ct": 1},
              out_of_scope={"depth_limit": 1, "ct_name_outside_approved_domains": 4},
              truncations=[Truncation("max_hostnames", 3, "second"), Truncation("max_queries", 1, "q")])

        self.assertEqual(self.store.evidence(self.run_id), [ev(1), rdap_ok, rdap_err])
        self.assertEqual(self.store.evidence(self.run_id, ["ev:2", "ev:missing", "ev:1"]), [rdap_ok, ev(1)])
        self.assertEqual(self.store.rdap_cache(self.run_id), [rdap_ok])
        self.assertEqual(self.store.relationships(self.run_id), [rel("rel:1", ["ev:1"])])
        assets = self.store.assets(self.run_id)
        self.assertEqual(assets[0], {"asset": Asset("hostname:a.example.com", "hostname", "a.example.com"),
                                     "seed_id": "seed:1", "depth": 1, "path_relationship_id": "rel:1"})
        self.assertEqual(self.store.asset_count(self.run_id, "ip"), 1)
        self.assertTrue(self.store.has_asset(self.run_id, "ip:198.51.100.1"))
        self.assertFalse(self.store.has_asset(self.run_id, "ip:198.51.100.2"))

        run = self.store.run(self.run_id)
        self.assertEqual(run["query_count"], 5)
        self.assertEqual(run["source_failures"], {"rdap": 3, "ct": 1})
        self.assertEqual(run["out_of_scope"], {"depth_limit": 3, "ct_name_outside_approved_domains": 4})
        self.assertEqual(run["truncated"], [{"limit": "max_hostnames", "omitted": 5, "detail": "second"},
                                            {"limit": "max_queries", "omitted": 1, "detail": "q"}])
        counts = run["counts"]
        self.assertEqual((counts["tasks_pending"], counts["tasks_done"], counts["assets"]), (1, 1, 2))
        self.assertEqual((counts["coverage_checked"], counts["coverage_no_record"]), (2, 1))

    def test_atomic_on_failure(self):
        self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:1", 0, None)])
        task_id = self.store.pending_tasks(self.run_id, 1)[0]["id"]

        def exploding():
            yield rel("rel:1", ["ev:1"])
            raise RuntimeError("mid-commit failure")

        with self.assertRaises(RuntimeError):
            batch(self.store, self.run_id, done_task_ids=[task_id], evidence=[ev(1)],
                  assets=[(Asset("hostname:a.example.com", "hostname", "a.example.com"), "seed:1", 1, "rel:1")],
                  relationships=exploding(), queries=5, source_failures={"ct": 1},
                  coverage=[("198.51.100.1", "internetdb", "ok", "t")])
        self.assertEqual(self.store.evidence(self.run_id), [])
        self.assertEqual(self.store.assets(self.run_id), [])
        self.assertEqual(self.store.relationships(self.run_id), [])
        self.assertEqual(list(self.store.coverage(self.run_id)), [])
        self.assertEqual(len(self.store.pending_tasks(self.run_id, 10)), 1)
        run = self.store.run(self.run_id)
        self.assertEqual((run["query_count"], run["source_failures"]), (0, {}))

    def test_first_path_wins(self):
        a = Asset("ip:198.51.100.9", "ip", "198.51.100.9")
        batch(self.store, self.run_id, assets=[(a, "seed:1", 1, "rel:first"), (a, "seed:2", 0, "rel:dup")])
        batch(self.store, self.run_id, assets=[(a, "seed:2", 2, "rel:later"),
                                               (Asset("hostname:b.example.com", "hostname", "b.example.com"),
                                                "seed:1", 1, "rel:b")])
        rows = self.store.assets(self.run_id)
        self.assertEqual([r["asset"].id for r in rows], ["ip:198.51.100.9", "hostname:b.example.com"])
        self.assertEqual((rows[0]["seed_id"], rows[0]["depth"], rows[0]["path_relationship_id"]),
                         ("seed:1", 1, "rel:first"))

    def test_relationship_evidence_merge(self):
        batch(self.store, self.run_id, relationships=[rel("rel:1", ["ev:1", "ev:2"]), rel("rel:2", ["ev:9"])])
        batch(self.store, self.run_id, relationships=[rel("rel:1", ["ev:2", "ev:3", "ev:3"])])
        rels = self.store.relationships(self.run_id)
        self.assertEqual([r.id for r in rels], ["rel:1", "rel:2"])
        self.assertEqual(rels[0].evidence_ids, ("ev:1", "ev:2", "ev:3"))
        self.assertIsInstance(rels[0].evidence_ids, tuple)

    def test_duplicate_evidence_ignored(self):
        batch(self.store, self.run_id, evidence=[ev(1), ev(1)])
        batch(self.store, self.run_id, evidence=[ev(1)])
        self.assertEqual(self.store.evidence(self.run_id), [ev(1)])

    def test_coverage_numeric_order_and_upsert(self):
        batch(self.store, self.run_id, coverage=[("198.51.100.10", "internetdb", "ok", "t1"),
                                                 ("198.51.100.9", "internetdb", "no_record", "t1"),
                                                 ("9.9.9.9", "internetdb", "error", "t1"),
                                                 ("198.51.100.9", "rdap", "ok", "t1")])
        batch(self.store, self.run_id, coverage=[("9.9.9.9", "internetdb", "no_record", "t2")])
        rows = list(self.store.coverage(self.run_id))
        self.assertEqual([(r["ip"], r["source"]) for r in rows],
                         [("9.9.9.9", "internetdb"), ("198.51.100.9", "internetdb"), ("198.51.100.9", "rdap"),
                          ("198.51.100.10", "internetdb")])
        self.assertEqual(rows[0], {"ip": "9.9.9.9", "source": "internetdb", "status": "no_record",
                                   "retrieved_at": "t2"})
        counts = self.store.run(self.run_id)["counts"]
        self.assertEqual((counts["coverage_checked"], counts["coverage_no_record"]), (4, 2))

    def test_concurrent_readers_and_writer(self):
        errors = []

        def writer():
            try:
                for i in range(40):
                    batch(self.store, self.run_id, coverage=[(f"10.0.{i}.1", "internetdb", "ok", "t")], queries=1)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        def reader():
            try:
                for _ in range(40):
                    self.store.run(self.run_id)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=writer), threading.Thread(target=writer)] + \
                  [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.store.run(self.run_id)["query_count"], 80)


class AssessmentTests(StoreTestCase):
    def setUp(self):
        super().setUp()
        self.findings = [
            finding("a.example.com", "new", 3.2, ("no_resolution",)),
            finding("b.example.com", "new", 3.2, ("conflict", "potential_vulns")),
            finding("c.example.com", "known", 0.1),
            finding("198.51.100.1", "third_party", 1.3, ("conflict",), type_="ip"),
            finding("x_y.example.com", "unexplained", 2.0, ("inventory_match_indeterminate",)),
            finding("100%.example.com", "unexplained", 2.5),
            finding("UPPER.example.com", "unexplained", 2.5),
        ]
        self.assertions = [Assertion(id="as:hostname:a.example.com:ownership", asset_id="hostname:a.example.com",
                                     dimension="ownership", value="example.com", assessment="supported",
                                     supporting_evidence_ids=("ev:seed:1",), contradicting_evidence_ids=(),
                                     rationale="approved TICKET-1")]
        self.matches = [f.inventory_match for f in self.findings]
        self.store.save_assessment(self.run_id, "snap:1", self.assertions, self.matches, self.findings)

    def test_round_trip(self):
        self.assertEqual(self.store.assertions(self.run_id), self.assertions)
        self.assertEqual(self.store.inventory_matches(self.run_id), self.matches)
        got = self.store.finding(self.run_id, "fd:hostname:b.example.com")
        self.assertEqual(got, self.findings[1])
        self.assertIsInstance(got.inventory_match, InventoryMatch)
        self.assertIsInstance(got.flags, tuple)
        self.assertIsNone(self.store.finding(self.run_id, "fd:nope"))
        run = self.store.run(self.run_id)
        self.assertEqual(run["inventory_snapshot_id"], "snap:1")
        c = run["counts"]
        self.assertEqual((c["findings"], c["queue_new"], c["queue_known"], c["queue_unexplained"],
                          c["queue_third_party"]), (7, 2, 1, 3, 1))

    def test_replace_assessment(self):
        self.store.save_assessment(self.run_id, "snap:2", [], [], [finding("z.example.com", "known", 0.0)])
        items, total = self.store.findings(self.run_id)
        self.assertEqual((total, [f.value for f in items]), (1, ["z.example.com"]))
        self.assertEqual(self.store.assertions(self.run_id), [])
        self.assertEqual(self.store.run(self.run_id)["inventory_snapshot_id"], "snap:2")

    def values(self, **kw):
        items, total = self.store.findings(self.run_id, **kw)
        return [f.value for f in items], total

    def test_sorts(self):
        self.assertEqual(self.values()[0], ["a.example.com", "b.example.com", "100%.example.com", "UPPER.example.com",
                                            "x_y.example.com", "198.51.100.1", "c.example.com"])
        self.assertEqual(self.values(sort="value")[0][:2], ["100%.example.com", "198.51.100.1"])
        self.assertEqual(self.values(sort="queue")[0], ["c.example.com", "a.example.com", "b.example.com",
                                                        "100%.example.com", "UPPER.example.com", "x_y.example.com",
                                                        "198.51.100.1"])
        with self.assertRaises(ValueError):
            self.store.findings(self.run_id, sort="bogus")

    def test_filters_combine(self):
        self.assertEqual(self.values(queue="new"), (["a.example.com", "b.example.com"], 2))
        self.assertEqual(self.values(asset_type="ip"), (["198.51.100.1"], 1))
        self.assertEqual(self.values(flag="conflict"), (["b.example.com", "198.51.100.1"], 2))
        self.assertEqual(self.values(flag="conflict", queue="new"), (["b.example.com"], 1))
        self.assertEqual(self.values(flag="conf"), ([], 0))
        self.assertEqual(self.values(queue="new", asset_type="ip"), ([], 0))

    def test_search(self):
        self.assertEqual(self.values(search="upper"), (["UPPER.example.com"], 1))
        self.assertEqual(self.values(search="B.EXAMPLE"), (["b.example.com"], 1))
        self.assertEqual(self.values(search="%"), (["100%.example.com"], 1))
        self.assertEqual(self.values(search="_"), (["x_y.example.com"], 1))
        self.assertEqual(self.values(search="x_y"), (["x_y.example.com"], 1))
        self.assertEqual(self.values(search="0%."), (["100%.example.com"], 1))
        self.assertEqual(self.values(search="\\"), ([], 0))
        self.assertEqual(self.values(search="example", asset_type="hostname", queue="unexplained")[1], 3)

    def test_paging_and_clamp(self):
        items, total = self.store.findings(self.run_id, offset=2, limit=2)
        self.assertEqual(([f.value for f in items], total), (["100%.example.com", "UPPER.example.com"], 7))
        self.assertEqual(len(self.store.findings(self.run_id, limit=0)[0]), 1)
        self.assertEqual(len(self.store.findings(self.run_id, limit=10_000)[0]), 7)
        self.assertEqual(len(self.store.findings(self.run_id, offset=-5)[0]), 7)


class SnapshotTests(StoreTestCase):
    def snap(self, n, label):
        entries = tuple(InventoryEntry(f"inv:{i}", "ip", f"198.51.100.{i}", f"host {i}") for i in range(1, n + 1))
        return InventorySnapshot(id=f"snap:{label}", as_of="2026-10-01T00:00:00+00:00",
                                 imported_at="2026-10-16T00:00:00+00:00", label=label, entries=entries)

    def test_current_marker_and_idempotent_reimport(self):
        self.assertIsNone(self.store.current_snapshot())
        self.assertEqual(self.store.snapshots(), [])
        a, b = self.snap(3, "a"), self.snap(0, "b")
        self.store.save_snapshot(a)
        self.assertEqual(self.store.current_snapshot(), a)
        self.store.save_snapshot(b)
        self.assertEqual(self.store.current_snapshot(), b)
        self.assertEqual(self.store.snapshot("snap:a"), a)
        self.assertIsNone(self.store.snapshot("snap:zzz"))
        self.store.save_snapshot(a)  # re-import same content
        self.assertEqual(self.store.current_snapshot(), a)
        listing = self.store.snapshots()
        self.assertEqual([(s["id"], s["entry_count"], s["current"]) for s in listing],
                         [("snap:a", 3, True), ("snap:b", 0, False)])
        self.assertEqual(set(listing[0]), {"id", "as_of", "imported_at", "label", "entry_count", "current"})
        db = sqlite3.connect(self.path)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM inventory_entries").fetchone()[0], 3)
        db.close()


class CrashRecoveryTests(StoreTestCase):
    def test_recovery(self):
        pausing = self.store.create_run(make_config())
        queued = self.store.create_run(make_config())
        done = self.store.create_run(make_config())
        self.store.set_status(self.run_id, "running")
        self.store.set_status(pausing, "pausing")
        self.store.set_status(done, "complete")
        self.store.add_tasks(self.run_id, [("ct", "example.com", "seed:1", 0, None),
                                           ("dns", "example.com", "seed:1", 0, None)])
        db = sqlite3.connect(self.path)
        db.execute("UPDATE tasks SET status='running'")
        db.commit()
        db.close()

        store = Store(self.path)
        for rid in (self.run_id, pausing):
            run = store.run(rid)
            self.assertEqual((run["status"], run["last_error"]), ("paused", "Interrupted by restart."))
        self.assertEqual(store.run(queued)["status"], "queued")
        self.assertEqual(store.run(done)["status"], "complete")
        self.assertEqual(len(store.pending_tasks(self.run_id, 10)), 2)


if __name__ == "__main__":
    unittest.main()
