"""JSON, CSV and Markdown reports (docs/RULES.md section 7). Owner: reports/UI agent. Streams; never builds
the whole report in memory when it can be avoided.

All three formats are generated from the same store reads, so they list the same finding ids, queues and
assessments. Each generator yields UTF-8 encoded chunks.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable, Iterator

from .contracts import Finding
from .store import Store

DIMENSIONS = ("ownership", "operational_control", "hosting", "service_association")
QUEUES = ("new", "unexplained", "third_party", "known")
PAGE = 500
TOP_N = 20

CSV_COLUMNS = (
    "finding_id", "asset_id", "asset_type", "value", "queue", "role", "inventory_match", "match_rule",
    "inventory_entry", "ownership", "ownership_value", "operational_control", "operational_control_value",
    "hosting", "hosting_value", "service_association", "seed_id", "seed_path", "evidence_ids",
    "first_observed", "last_observed", "flags", "ports", "vulns", "rank",
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: object) -> str:
    """Text for one CSV cell. None becomes ""; any cell that a spreadsheet could read as a formula
    (leading = + - @ tab or carriage return) is prefixed with an apostrophe."""
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, float):
        text = f"{value:.2f}"
    elif isinstance(value, (list, tuple)):
        text = ";".join("" if item is None else str(item) for item in value)
    else:
        text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


_MD_SPECIAL = set("\\`*_{}[]()<>#+-.!|~&")


def md(value: object) -> str:
    """Escape source-derived text for inline Markdown: every Markdown/HTML control character is
    backslash-escaped and line breaks are flattened so a value can never start a new block."""
    if value is None:
        return ""
    text = " ".join(str(value).replace("\r", "\n").split("\n"))
    return "".join("\\" + ch if ch in _MD_SPECIAL else ch for ch in text)


# --------------------------------------------------------------------------- shared reads

def _run_or_raise(store: Store, run_id: str) -> dict[str, Any]:
    run = store.run(run_id)
    if run is None:
        raise KeyError(run_id)
    return run


def iter_findings(store: Store, run_id: str, **filters: Any) -> Iterator[Finding]:
    """Every finding in rank order, read page by page."""
    offset = 0
    while True:
        page, total = store.findings(run_id, offset=offset, limit=PAGE, **filters)
        yield from page
        offset += len(page)
        if not page or offset >= total:
            return


def _snapshot_summary(store: Store, run: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """(summary for the report header, entry id -> entry dict)."""
    snapshot_id = run.get("inventory_snapshot_id")
    if not snapshot_id:
        return None, {}
    snapshot = store.snapshot(snapshot_id)
    if snapshot is None:
        return {"id": snapshot_id, "as_of": None, "label": None, "entry_count": None}, {}
    entries = {entry.id: entry.to_dict() for entry in snapshot.entries}
    return ({"id": snapshot.id, "as_of": snapshot.as_of, "label": snapshot.label,
             "entry_count": len(snapshot.entries)}, entries)


def _approval_refs(run: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for seed in run.get("config", {}).get("seeds", []):
        ref = seed.get("approval_ref")
        if ref and ref not in refs:
            refs.append(ref)
    return refs


def _coverage_summary(run: dict[str, Any]) -> dict[str, Any]:
    counts = run.get("counts") or {}
    checked = counts.get("coverage_checked") or 0
    no_record = counts.get("coverage_no_record") or 0
    return {"checked": checked, "no_record": no_record}


def run_header(store: Store, run: dict[str, Any]) -> dict[str, Any]:
    snapshot, _ = _snapshot_summary(store, run)
    return {
        "id": run["id"], "status": run.get("status"), "label": run.get("label"),
        "created_at": run.get("created_at"), "finished_at": run.get("finished_at"),
        "config": run.get("config"), "approval_refs": _approval_refs(run),
        "inventory_snapshot": snapshot, "truncated": run.get("truncated") or [],
        "out_of_scope": run.get("out_of_scope") or {}, "source_failures": run.get("source_failures") or {},
        "query_count": run.get("query_count") or 0, "coverage_summary": _coverage_summary(run),
        "flags": run.get("flags") or [],
    }


def report_filename(run_id: str, extension: str) -> str:
    return f"averiguao-{run_id[:8]}.{extension}"


def _seed_values(run: dict[str, Any]) -> dict[str, str]:
    return {seed["id"]: seed["value"] for seed in run.get("config", {}).get("seeds", [])}


def _asset_value(asset_id: str) -> str:
    return asset_id.split(":", 1)[1] if ":" in asset_id else asset_id


def _path_ids(finding: Finding, relationships: dict[str, Any]) -> list[str]:
    """seed id followed by every asset id along the finding's path."""
    chain = [finding.seed_id]
    for rel_id in finding.path:
        rel = relationships.get(rel_id)
        if rel is None:
            continue
        if not chain or chain[-1] != rel.subject_id:
            if rel.subject_id not in chain:
                chain.append(rel.subject_id)
        chain.append(rel.object_id)
    return chain


def _ports_vulns(finding: Finding, evidence: dict[str, Any]) -> tuple[list[str], list[str]]:
    ports: set[int] = set()
    vulns: set[str] = set()
    for ev_id in finding.evidence_ids:
        ev = evidence.get(ev_id)
        if ev is None or ev.source != "internetdb" or ev.query != finding.value:
            continue
        for port in ev.data.get("ports") or []:
            if isinstance(port, int):
                ports.add(port)
        for vuln in ev.data.get("vulns") or []:
            vulns.add(str(vuln))
    return [str(p) for p in sorted(ports)], sorted(vulns)


# --------------------------------------------------------------------------- JSON

def _dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_array(key: str, items: Iterable[Any], first_key: bool = False) -> Iterator[bytes]:
    yield (b"" if first_key else b",") + _dumps(key) + b":["
    first = True
    for item in items:
        yield (b"" if first else b",") + _dumps(item)
        first = False
    yield b"]"


def json_report(store: Store, run_id: str) -> Iterator[bytes]:
    run = _run_or_raise(store, run_id)
    header = run_header(store, run)

    def assets() -> Iterator[dict[str, Any]]:
        for row in store.assets(run_id):
            item = row["asset"].to_dict()
            item.update(seed_id=row.get("seed_id"), depth=row.get("depth"),
                        path_relationship_id=row.get("path_relationship_id"))
            yield item

    def matches() -> Iterator[dict[str, Any]]:
        for finding in iter_findings(store, run_id):
            yield finding.inventory_match.to_dict()

    yield b'{"run":' + _dumps(header)
    yield from _json_array("seeds", run.get("config", {}).get("seeds", []))
    yield from _json_array("assets", assets())
    yield from _json_array("evidence", (ev.to_dict() for ev in store.evidence(run_id)))
    yield from _json_array("relationships", (rel.to_dict() for rel in store.relationships(run_id)))
    yield from _json_array("assertions", (a.to_dict() for a in store.assertions(run_id)))
    yield from _json_array("inventory_matches", matches())
    yield from _json_array("findings", (f.to_dict() for f in iter_findings(store, run_id)))
    yield from _json_array("coverage", store.coverage(run_id))
    yield b"}\n"


# --------------------------------------------------------------------------- CSV

def _csv_line(cells: Iterable[object]) -> bytes:
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\r\n").writerow([safe_cell(cell) for cell in cells])
    return buffer.getvalue().encode("utf-8")


def csv_report(store: Store, run_id: str) -> Iterator[bytes]:
    run = _run_or_raise(store, run_id)
    _, entries = _snapshot_summary(store, run)
    assertions = {a.id: a for a in store.assertions(run_id)}
    relationships = {r.id: r for r in store.relationships(run_id)}
    evidence = {e.id: e for e in store.evidence(run_id)}
    yield _csv_line(CSV_COLUMNS)
    for finding in iter_findings(store, run_id):
        by_dim = {}
        for as_id in finding.assertion_ids:
            assertion = assertions.get(as_id)
            if assertion is not None:
                by_dim[assertion.dimension] = assertion
        match = finding.inventory_match
        entry = entries.get(match.entry_id) if match.entry_id else None
        entry_text = f"{entry['value']}" if entry else (match.entry_id or "")
        ports, vulns = _ports_vulns(finding, evidence)

        def dim(name: str, field: str) -> object:
            a = by_dim.get(name)
            return getattr(a, field) if a is not None else None

        yield _csv_line([
            finding.id, finding.asset_id, finding.asset_type, finding.value, finding.queue, finding.role,
            match.status, match.rule, entry_text,
            dim("ownership", "assessment"), dim("ownership", "value"),
            dim("operational_control", "assessment"), dim("operational_control", "value"),
            dim("hosting", "assessment"), dim("hosting", "value"),
            dim("service_association", "assessment"),
            finding.seed_id, _path_ids(finding, relationships), list(finding.evidence_ids),
            finding.first_observed, finding.last_observed, list(finding.flags), ports, vulns,
            finding.rank,
        ])


# --------------------------------------------------------------------------- Markdown

_SOURCE_LABEL = {"ct": "CT", "dns": "DNS", "rdap": "RDAP", "internetdb": "InternetDB", "scope": "scope"}


def _evidence_path(finding: Finding, relationships: dict[str, Any], evidence: dict[str, Any],
                   seeds: dict[str, str]) -> str:
    parts = [f"{md(finding.seed_id)} {md(seeds.get(finding.seed_id, ''))}"]
    for rel_id in finding.path:
        rel = relationships.get(rel_id)
        if rel is None:
            parts.append(f"→ \\[missing {md(rel_id)}\\]")
            continue
        if rel.predicate == "seed_is":
            continue
        ev_id = rel.evidence_ids[0] if rel.evidence_ids else None
        ev = evidence.get(ev_id) if ev_id else None
        source = _SOURCE_LABEL.get(ev.source, ev.source) if ev is not None else "?"
        parts.append(f"→ \\[{md(source)} {md(ev_id or 'no evidence')}\\] {md(_asset_value(rel.object_id))}")
    return " ".join(parts)


def _table(header: list[str], rows: Iterable[list[str]]) -> Iterator[str]:
    yield "| " + " | ".join(header) + " |\n"
    yield "|" + "|".join(" --- " for _ in header) + "|\n"
    for row in rows:
        yield "| " + " | ".join(row) + " |\n"


def markdown_report(store: Store, run_id: str) -> Iterator[bytes]:
    run = _run_or_raise(store, run_id)
    header = run_header(store, run)
    seeds = _seed_values(run)
    config = run.get("config") or {}
    relationships = {r.id: r for r in store.relationships(run_id)}
    evidence = {e.id: e for e in store.evidence(run_id)}
    assertions = {a.id: a for a in store.assertions(run_id)}

    def out(text: str) -> bytes:
        return text.encode("utf-8")

    title = run.get("label") or run_id[:8]
    yield out(f"# Averiguao run {md(title)}\n\n")
    yield out(f"- Run id: {md(run_id)}\n- Status: {md(run.get('status'))}\n")
    yield out(f"- Created: {md(run.get('created_at'))}; finished: {md(run.get('finished_at') or 'not finished')}\n")
    yield out(f"- Approval references: {', '.join(md(r) for r in header['approval_refs']) or 'none'}\n")
    org_names = config.get("org_names") or []
    yield out(f"- Organization names: {', '.join(md(o) for o in org_names) or 'none (IP ownership cannot be supported)'}\n")
    snap = header["inventory_snapshot"]
    if snap:
        yield out(f"- Inventory snapshot: {md(snap['label'] or '(no label)')} ({md(snap['id'])}), as of "
                  f"{md(snap['as_of'])}, {snap['entry_count'] if snap['entry_count'] is not None else '?'} entries\n")
    else:
        yield out("- Inventory snapshot: none (run not assessed)\n")
    limits = config.get("limits") or {}
    if limits:
        yield out("- Limits: " + ", ".join(f"{md(k)} {md(v)}" for k, v in limits.items()) + "\n")
    rules = config.get("match_rules") or {}
    if rules:
        yield out("- Match rules: " + ", ".join(f"{md(k)} {'on' if v else 'off'}" for k, v in rules.items()) + "\n")
    yield out(f"- Queries: {header['query_count']}\n\n")

    yield out("## Seeds\n\n")
    for seed in config.get("seeds") or []:
        yield out(f"- {md(seed.get('id'))} {md(seed.get('type'))} {md(seed.get('value'))} "
                  f"(approval {md(seed.get('approval_ref'))})\n")
    yield out("\n")

    warnings: list[str] = []
    for item in header["truncated"]:
        warnings.append(f"**Truncated** by {md(item.get('limit'))}: {md(item.get('omitted'))} omitted. "
                        f"{md(item.get('detail'))}")
    for source, count in sorted(header["source_failures"].items()):
        warnings.append(f"**Source failures**: {md(source)} failed {md(count)} time(s); affected assets carry "
                        f"the flag source\\_error.")
    if "empty_inventory" in header["flags"]:
        warnings.append("**Empty inventory**: no inventory snapshot existed when the run completed, so nothing "
                        "can be Known.")
    if run.get("last_error"):
        warnings.append(f"**Last error**: {md(run.get('last_error'))}")
    if warnings:
        yield out("## Warnings\n\n")
        for warning in warnings:
            yield out(f"> {warning}\n>\n")
        yield out("\n")
    if header["out_of_scope"]:
        yield out("Out-of-scope observations (counted, not recorded): " + ", ".join(
            f"{md(reason)} {md(n)}" for reason, n in sorted(header["out_of_scope"].items())) + "\n\n")

    counts = {q: 0 for q in QUEUES}
    top: dict[str, list[Finding]] = {"new": [], "unexplained": []}
    third: list[Finding] = []
    conflicts: list[Finding] = []
    stale: list[Finding] = []
    total = 0
    for finding in iter_findings(store, run_id):
        total += 1
        counts[finding.queue] = counts.get(finding.queue, 0) + 1
        if finding.queue in top and len(top[finding.queue]) < TOP_N:
            top[finding.queue].append(finding)
        if finding.queue == "third_party":
            third.append(finding)
        if "conflict" in finding.flags:
            conflicts.append(finding)
        if "stale_evidence" in finding.flags:
            stale.append(finding)

    yield out("## Findings by queue\n\n")
    yield from (out(line) for line in _table(
        ["Queue", "Findings"], ([md(q), str(counts.get(q, 0))] for q in QUEUES)))
    yield out(f"\nTotal findings: {total}\n\n")

    def assessment(f: Finding, dimension: str) -> str:
        a = assertions.get(f"as:{f.asset_id}:{dimension}")
        if a is None:
            return "?"
        return md(a.assessment) + (f" ({md(a.value)})" if a.value else "")

    def finding_rows(items: list[Finding]) -> Iterator[list[str]]:
        for f in items:
            yield [md(f.value), md(f.asset_type), md(f.role), assessment(f, "ownership"),
                   assessment(f, "operational_control"), assessment(f, "hosting"),
                   md(", ".join(f.flags)) or "", f"{f.rank:.2f}"]

    columns = ["Value", "Type", "Role", "Ownership", "Control", "Hosting", "Flags", "Rank"]
    listed: list[Finding] = []
    for queue, heading in (("new", "New (top 20 by rank)"), ("unexplained", "Unexplained (top 20 by rank)")):
        yield out(f"## {heading}\n\n")
        if top[queue]:
            yield from (out(line) for line in _table(columns, finding_rows(top[queue])))
            listed.extend(top[queue])
        else:
            yield out("None.\n")
        yield out("\n")

    yield out("## Third-party dependencies\n\n")
    if third:
        yield from (out(line) for line in _table(
            ["Value", "Type", "Operator", "Hosting"],
            ([md(f.value), md(f.asset_type), assessment(f, "operational_control"), assessment(f, "hosting")]
             for f in third)))
    else:
        yield out("None.\n")
    yield out("\n## Conflicts\n\n")
    if conflicts:
        for f in conflicts:
            yield out(f"- {md(f.value)} ({md(f.queue)}): " + "; ".join(
                f"{md(d)} {assessment(f, d)}" for d in DIMENSIONS) + "\n")
    else:
        yield out("None.\n")
    yield out("\n## Stale evidence\n\n")
    if stale:
        for f in stale:
            yield out(f"- {md(f.value)} ({md(f.queue)}), last observed validity ended before completion\n")
    else:
        yield out("None.\n")

    listed.extend(third)
    yield out("\n## Evidence paths\n\n")
    if listed:
        for f in listed:
            yield out(f"- {md(f.id)}: {_evidence_path(f, relationships, evidence, seeds)}\n")
    else:
        yield out("No New, Unexplained or Third-party findings listed.\n")

    yield out("\n## All findings\n\n")
    if total:
        yield from (out(line) for line in _table(
            ["Finding id", "Value", "Queue", "Role"],
            ([md(f.id), md(f.value), md(f.queue), md(f.role)] for f in iter_findings(store, run_id))))
    else:
        yield out("None.\n")
