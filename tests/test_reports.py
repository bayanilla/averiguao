"""Reports (docs/RULES.md section 7): format agreement, CSV injection guard, Markdown escaping, streaming."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import types
import unittest

from averiguao_core import reports
from averiguao_core.connectors.fake import DEMO_CONFIG, DEMO_INVENTORY_CSV, demo_world
from averiguao_core.contracts import (Assertion, Asset, Evidence, Finding, InventoryEntry, InventoryMatch,
                                      InventorySnapshot, Relationship)
from tests.fixtures.pipeline import run_pipeline

DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def collect(gen) -> bytes:
    return b"".join(gen)


class HostileStore:
    """Duck-typed store whose every source-derived field is hostile, to test escaping in every column."""

    RUN_ID = "f" * 32

    def __init__(self, n: int = 3):
        evil = "=HYPERLINK(\"http://x\")"
        self.evidence_list = [
            Evidence(id="ev:1", source="internetdb", query="+1.2.3.4", source_url="@url", raw_sha256="-sha",
                     observed_at="=2026", valid_from=None, valid_to=None, source_record_id=None,
                     data={"ports": [443], "vulns": ["+cmd|' /C calc'!A0"]}),
            Evidence(id="ev:2", source="ct", query="example.com", source_url="u", raw_sha256=None,
                     observed_at="2026", valid_from=None, valid_to=None, source_record_id=None, data={}),
        ]
        self.rels = [
            Relationship(id="rel:1", subject_id="seed:1", predicate="seed_is", object_id="domain:example.com",
                         evidence_ids=("ev:2",), seed_id="seed:1", depth=0),
            Relationship(id="rel:2", subject_id="domain:example.com", predicate="certificate_mentions_hostname",
                         object_id="hostname:*evil*_[x](http://e)<script>|x", evidence_ids=("ev:2",),
                         seed_id="seed:1", depth=1),
        ]
        self.findings_list = []
        self.assertion_list = []
        for i in range(n):
            asset = f"ip:={i}"
            ids = []
            for dim in ("ownership", "operational_control", "hosting", "service_association"):
                aid = f"as:{asset}:{dim}"
                ids.append(aid)
                self.assertion_list.append(Assertion(id=aid, asset_id=asset, dimension=dim, value=evil,
                                                     assessment="-supported", supporting_evidence_ids=("ev:1",),
                                                     contradicting_evidence_ids=(), rationale="@r"))
            self.findings_list.append(Finding(
                id=f"=fd{i}", asset_id=asset, asset_type="\tip", value="+" + "1.2.3.4" if i else
                "*evil*_[x](http://e)<script>|x\nnext line", queue="new", role="@role",
                inventory_match=InventoryMatch(asset_id=asset, snapshot_id="snap:x", entry_id="inv:1",
                                               rule="-rule", status="=status"),
                assertion_ids=tuple(ids), seed_id="seed:1", path=("rel:1", "rel:2"), evidence_ids=("ev:1",),
                first_observed="\r2026", last_observed="@2026", flags=("-flag",), rank=-0.3))

    def run(self, run_id):
        if run_id != self.RUN_ID:
            return None
        return {"id": self.RUN_ID, "status": "complete", "label": "=label", "created_at": "c", "finished_at": "f",
                "config": {"seeds": [{"id": "seed:1", "type": "domain", "value": "example.com",
                                      "approval_ref": "[click](http://evil)", "scope_version": "1"}],
                           "org_names": ["**Org**"], "limits": {"max_depth": 2}, "match_rules": {"exact": True}},
                "inventory_snapshot_id": "snap:x", "truncated": [{"limit": "max_queries", "omitted": 4,
                                                                  "detail": "<b>stop</b>"}],
                "out_of_scope": {"depth_limit": 1}, "source_failures": {"internetdb": 2}, "query_count": 9,
                "counts": {"coverage_checked": 1, "coverage_no_record": 0}, "flags": [], "last_error": None}

    def snapshot(self, snapshot_id):
        return InventorySnapshot(id="snap:x", as_of="a", imported_at="i", label="l",
                                 entries=(InventoryEntry(id="inv:1", kind="cidr", value="-10.0.0.0/8", label="x"),))

    def findings(self, run_id, *, offset=0, limit=100, **_):
        return self.findings_list[offset:offset + limit], len(self.findings_list)

    def assertions(self, run_id):
        return list(self.assertion_list)

    def relationships(self, run_id):
        return list(self.rels)

    def evidence(self, run_id, ids=None):
        return list(self.evidence_list)

    def assets(self, run_id):
        return [{"asset": Asset(id=f.asset_id, type="ip", value=f.value), "seed_id": "seed:1", "depth": 1,
                 "path_relationship_id": "rel:2"} for f in self.findings_list]

    def coverage(self, run_id):
        return iter([{"ip": "1.2.3.4", "source": "internetdb", "status": "ok", "retrieved_at": "t"}])


class SafeCellTest(unittest.TestCase):
    def test_prefixes(self):
        for prefix in DANGEROUS:
            self.assertEqual(reports.safe_cell(prefix + "x"), "'" + prefix + "x")
        self.assertEqual(reports.safe_cell("example.com"), "example.com")
        self.assertEqual(reports.safe_cell(None), "")
        self.assertEqual(reports.safe_cell(["-a", "b"]), "'-a;b")
        self.assertEqual(reports.safe_cell(-0.3), "'-0.30")
        self.assertEqual(reports.safe_cell(1.5), "1.50")


class HostileReportTest(unittest.TestCase):
    def setUp(self):
        self.store = HostileStore()

    def test_every_csv_cell_is_guarded(self):
        text = collect(reports.csv_report(self.store, HostileStore.RUN_ID)).decode("utf-8")
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(tuple(rows[0]), reports.CSV_COLUMNS)
        self.assertEqual(len(rows), 1 + len(self.store.findings_list))
        for row in rows[1:]:
            self.assertEqual(len(row), len(reports.CSV_COLUMNS))
            for column, cell in zip(reports.CSV_COLUMNS, row):
                self.assertFalse(cell.startswith(DANGEROUS), f"{column} cell {cell!r} is not guarded")
        # the columns that were deliberately hostile in the fixture all got the apostrophe
        hostile = dict(zip(reports.CSV_COLUMNS, rows[2]))
        for column in ("finding_id", "asset_type", "value", "role", "inventory_match", "match_rule", "inventory_entry",
                       "ownership", "ownership_value", "operational_control", "operational_control_value", "hosting",
                       "hosting_value", "service_association", "first_observed", "last_observed", "flags", "vulns",
                       "rank"):
            self.assertTrue(hostile[column].startswith("'"), f"{column}: {hostile[column]!r}")
        self.assertIn("'+cmd", text)

    def test_markdown_escapes_source_text(self):
        text = collect(reports.markdown_report(self.store, HostileStore.RUN_ID)).decode("utf-8")
        self.assertNotIn("<script>", text)
        self.assertNotIn("<b>", text)
        self.assertNotIn("[click](http://evil)", text)
        self.assertNotIn("**Org**", text)
        self.assertIn("\\*evil\\*\\_\\[x\\]\\(http://e\\)\\<script\\>\\|x next line", text)
        self.assertIn("\\[click\\]\\(http://evil\\)", text)
        self.assertNotIn("\nnext line", text)
        self.assertIn("Truncated", text)
        self.assertIn("Source failures", text)

    def test_md_helper(self):
        self.assertEqual(reports.md("a_b*c"), "a\\_b\\*c")
        self.assertEqual(reports.md("x\r\ny"), "x  y")
        self.assertEqual(reports.md(None), "")

    def test_json_streams_and_parses(self):
        gen = reports.json_report(self.store, HostileStore.RUN_ID)
        self.assertTrue(isinstance(gen, types.GeneratorType))
        chunks = list(gen)
        self.assertGreater(len(chunks), 10)
        data = json.loads(b"".join(chunks))
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(data["run"]["approval_refs"], ["[click](http://evil)"])

    def test_unknown_run_raises(self):
        for fn in (reports.json_report, reports.csv_report, reports.markdown_report):
            with self.assertRaises(KeyError):
                collect(fn(self.store, "0" * 32))


class PipelineReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store, cls.run_id = run_pipeline(demo_world(), DEMO_CONFIG, DEMO_INVENTORY_CSV, tmpdir=cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_formats_agree(self):
        data = json.loads(collect(reports.json_report(self.store, self.run_id)))
        rows = list(csv.DictReader(io.StringIO(collect(reports.csv_report(self.store, self.run_id)).decode())))
        markdown = collect(reports.markdown_report(self.store, self.run_id)).decode().replace("\\", "")
        json_findings = {f["id"]: f for f in data["findings"]}
        csv_findings = {r["finding_id"]: r for r in rows}
        self.assertEqual(set(json_findings), set(csv_findings))
        self.assertGreater(len(json_findings), 5)
        assertions = {a["id"]: a for a in data["assertions"]}
        for fid, f in json_findings.items():
            row = csv_findings[fid]
            self.assertEqual(row["queue"], f["queue"])
            self.assertEqual(row["role"], f["role"])
            self.assertIn(fid, markdown)
            for dim in ("ownership", "operational_control", "hosting", "service_association"):
                self.assertEqual(row[dim], assertions[f"as:{f['asset_id']}:{dim}"]["assessment"])
        counts = {}
        for f in json_findings.values():
            counts[f["queue"]] = counts.get(f["queue"], 0) + 1
        for queue, n in counts.items():
            self.assertIn(f"| {queue} | {n} |", markdown)
        self.assertEqual(len(data["inventory_matches"]), len(json_findings))
        self.assertEqual(data["run"]["inventory_snapshot"]["entry_count"], 3)
        self.assertTrue(data["coverage"])
        self.assertIn("→", markdown)

    def test_streaming_yields_many_chunks(self):
        for fn in (reports.json_report, reports.csv_report, reports.markdown_report):
            gen = fn(self.store, self.run_id)
            self.assertIsInstance(gen, types.GeneratorType)
            self.assertGreater(sum(1 for _ in gen), 5)

    def test_filename(self):
        self.assertEqual(reports.report_filename(self.run_id, "csv"), f"averiguao-{self.run_id[:8]}.csv")


if __name__ == "__main__":
    unittest.main()
