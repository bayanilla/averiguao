"""SQLite persistence for runs, tasks, discovery records, assessments and inventory snapshots.

Owner: store/runner agent. Single file database, WAL mode, one short-lived connection per call (thread-safe).
All JSON-ish fields are stored as JSON text and returned as Python objects / contract records.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .contracts import (Assertion, Asset, Evidence, Finding, InventoryEntry, InventoryMatch, InventorySnapshot,
                        Limits, MatchRules, Relationship, RunConfig, RunStatus, Seed, Truncation)

DEFAULT_DB = Path(__file__).resolve().parent.parent / ".averiguao" / "averiguao.sqlite3"

SCHEMA_VERSION = 1
RUN_STATUSES = ("queued", "running", "pausing", "paused", "complete", "failed")
QUEUE_ORDER = {"known": 0, "new": 1, "unexplained": 2, "third_party": 3}
_FINDING_SORTS = {
    "rank": "rank DESC, value ASC, id ASC",
    "value": "value ASC, id ASC",
    "queue": "queue_order ASC, rank DESC, value ASC, id ASC",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    status TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    config TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    last_error TEXT,
    inventory_snapshot_id TEXT,
    query_count INTEGER NOT NULL DEFAULT 0,
    source_failures TEXT NOT NULL DEFAULT '{}',
    out_of_scope TEXT NOT NULL DEFAULT '{}',
    truncated TEXT NOT NULL DEFAULT '[]',
    flags TEXT NOT NULL DEFAULT '[]',
    elapsed_seconds REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_by_status ON runs(status, seq);
CREATE INDEX IF NOT EXISTS runs_by_seq ON runs(seq);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    query TEXT NOT NULL,
    seed_id TEXT NOT NULL,
    depth INTEGER NOT NULL,
    from_asset_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','done','skipped')),
    UNIQUE (run_id, source, query)
);
CREATE INDEX IF NOT EXISTS tasks_by_status ON tasks(run_id, status, id);

CREATE TABLE IF NOT EXISTS evidence (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    source TEXT NOT NULL,
    query TEXT NOT NULL,
    source_url TEXT NOT NULL,
    raw_sha256 TEXT,
    observed_at TEXT NOT NULL,
    valid_from TEXT,
    valid_to TEXT,
    source_record_id TEXT,
    ok INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (run_id, id)
);
CREATE INDEX IF NOT EXISTS evidence_by_source ON evidence(run_id, source, ok, seq);
CREATE INDEX IF NOT EXISTS evidence_by_seq ON evidence(run_id, seq);

CREATE TABLE IF NOT EXISTS assets (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    seed_id TEXT NOT NULL,
    depth INTEGER NOT NULL,
    path_relationship_id TEXT,
    seq INTEGER NOT NULL,
    PRIMARY KEY (run_id, asset_id)
);
CREATE INDEX IF NOT EXISTS assets_by_seq ON assets(run_id, seq);
CREATE INDEX IF NOT EXISTS assets_by_type ON assets(run_id, type);

CREATE TABLE IF NOT EXISTS relationships (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    subject_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_id TEXT NOT NULL,
    evidence_ids TEXT NOT NULL,
    seed_id TEXT NOT NULL,
    depth INTEGER NOT NULL,
    PRIMARY KEY (run_id, id)
);
CREATE INDEX IF NOT EXISTS relationships_by_seq ON relationships(run_id, seq);

CREATE TABLE IF NOT EXISTS coverage (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip_int INTEGER NOT NULL,
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    PRIMARY KEY (run_id, ip_int, source)
);
CREATE INDEX IF NOT EXISTS coverage_by_status ON coverage(run_id, status);

CREATE TABLE IF NOT EXISTS assertions (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    asset_id TEXT NOT NULL,
    dimension TEXT NOT NULL,
    assessment TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (run_id, id)
);
CREATE INDEX IF NOT EXISTS assertions_by_seq ON assertions(run_id, seq);

CREATE TABLE IF NOT EXISTS inventory_matches (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    snapshot_id TEXT NOT NULL,
    entry_id TEXT,
    rule TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (run_id, asset_id)
);
CREATE INDEX IF NOT EXISTS inventory_matches_by_seq ON inventory_matches(run_id, seq);

CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    queue TEXT NOT NULL,
    queue_order INTEGER NOT NULL,
    rank REAL NOT NULL,
    flags TEXT NOT NULL,          -- "|flag_a|flag_b|" for exact single-flag matching with instr()
    data TEXT NOT NULL,           -- full Finding.to_dict() JSON
    PRIMARY KEY (run_id, id)
);
CREATE INDEX IF NOT EXISTS findings_by_rank ON findings(run_id, rank DESC, value);
CREATE INDEX IF NOT EXISTS findings_by_queue ON findings(run_id, queue, rank DESC, value);
CREATE INDEX IF NOT EXISTS findings_by_value ON findings(run_id, value);

CREATE TABLE IF NOT EXISTS inventory_snapshots (
    id TEXT PRIMARY KEY,
    as_of TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    label TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    touched INTEGER NOT NULL      -- increases on every save/re-save, the highest is the current snapshot
);
CREATE INDEX IF NOT EXISTS inventory_snapshots_by_touched ON inventory_snapshots(touched);

CREATE TABLE IF NOT EXISTS inventory_entries (
    snapshot_id TEXT NOT NULL REFERENCES inventory_snapshots(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, position)
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=False)


def _ip_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _evidence_ok(ev: Evidence) -> bool:
    """Evidence has no status field; a result is 'ok' when it carries data and does not declare a failure."""
    data = ev.data or {}
    if not data:
        return False
    status = data.get("status")
    if status is not None and status != "ok":
        return False
    return not data.get("error")


def _config_from_dict(d: dict[str, Any]) -> RunConfig:
    return RunConfig(
        seeds=tuple(Seed(**s) for s in d.get("seeds", ())),
        org_names=tuple(d.get("org_names", ())),
        limits=Limits(**d.get("limits", {})),
        match_rules=MatchRules(**d.get("match_rules", {})),
        label=d.get("label", ""),
    )


def _evidence_from_row(row: sqlite3.Row) -> Evidence:
    return Evidence(id=row["id"], source=row["source"], query=row["query"], source_url=row["source_url"],
                    raw_sha256=row["raw_sha256"], observed_at=row["observed_at"], valid_from=row["valid_from"],
                    valid_to=row["valid_to"], source_record_id=row["source_record_id"], data=json.loads(row["data"]))


def _relationship_from_row(row: sqlite3.Row) -> Relationship:
    return Relationship(id=row["id"], subject_id=row["subject_id"], predicate=row["predicate"],
                        object_id=row["object_id"], evidence_ids=tuple(json.loads(row["evidence_ids"])),
                        seed_id=row["seed_id"], depth=row["depth"])


def _assertion_from_dict(d: dict[str, Any]) -> Assertion:
    d = dict(d)
    d["supporting_evidence_ids"] = tuple(d.get("supporting_evidence_ids", ()))
    d["contradicting_evidence_ids"] = tuple(d.get("contradicting_evidence_ids", ()))
    return Assertion(**d)


def _finding_from_dict(d: dict[str, Any]) -> Finding:
    d = dict(d)
    d["inventory_match"] = InventoryMatch(**d["inventory_match"])
    for key in ("assertion_ids", "path", "evidence_ids", "flags"):
        d[key] = tuple(d.get(key, ()))
    d["rank"] = float(d["rank"])
    return Finding(**d)


class Store:
    def __init__(self, path: Path = DEFAULT_DB):
        """Create schema if missing. Any run left 'running' or 'pausing' by a crash becomes 'paused' with
        last_error 'Interrupted by restart.'; its 'running' tasks go back to 'pending'."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=WAL")
        finally:
            db.close()
        with self._tx(write=True) as db:
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            row = db.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            if row["v"] is None:
                db.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row["v"] > SCHEMA_VERSION:
                raise RuntimeError(f"Database schema version {row['v']} is newer than supported ({SCHEMA_VERSION}).")
            now = utc_now()
            db.execute("UPDATE runs SET status='paused', last_error='Interrupted by restart.', updated_at=? "
                       "WHERE status IN ('running','pausing')", (now,))
            db.execute("UPDATE tasks SET status='pending' WHERE status='running'")

    @contextmanager
    def _tx(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        """One connection per call. Write transactions take the write lock up front (BEGIN IMMEDIATE) so
        read-modify-write sequences never fail with a stale WAL snapshot; reads get a consistent snapshot."""
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        finally:
            db.close()

    # ---- runs
    def create_run(self, config: RunConfig) -> str:
        """Insert a run with status 'queued'; return run id (uuid4 hex)."""
        run_id = uuid.uuid4().hex
        now = utc_now()
        with self._tx(write=True) as db:
            seq = db.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM runs").fetchone()[0]
            db.execute("INSERT INTO runs(id, seq, status, label, config, created_at, updated_at) "
                       "VALUES (?,?,?,?,?,?,?)",
                       (run_id, seq, "queued", config.label, _dumps(config.to_dict()), now, now))
        return run_id

    def _counts(self, db: sqlite3.Connection, run_id: str) -> dict[str, int]:
        counts = {"tasks_pending": 0, "tasks_done": 0, "assets": 0, "findings": 0,
                  "coverage_checked": 0, "coverage_no_record": 0, "queue_known": 0, "queue_new": 0,
                  "queue_unexplained": 0, "queue_third_party": 0}
        for row in db.execute("SELECT status, COUNT(*) AS n FROM tasks WHERE run_id=? GROUP BY status", (run_id,)):
            if row["status"] in ("pending", "running"):
                counts["tasks_pending"] += row["n"]
            elif row["status"] == "done":
                counts["tasks_done"] = row["n"]
        counts["assets"] = db.execute("SELECT COUNT(*) FROM assets WHERE run_id=?", (run_id,)).fetchone()[0]
        for row in db.execute("SELECT queue, COUNT(*) AS n FROM findings WHERE run_id=? GROUP BY queue", (run_id,)):
            counts["findings"] += row["n"]
            key = f"queue_{row['queue']}"
            if key in counts:
                counts[key] = row["n"]
        for row in db.execute("SELECT status, COUNT(*) AS n FROM coverage WHERE run_id=? GROUP BY status",
                              (run_id,)):
            counts["coverage_checked"] += row["n"]
            if row["status"] == "no_record":
                counts["coverage_no_record"] = row["n"]
        return counts

    def _run_dict(self, db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "status": row["status"], "label": row["label"],
            "config": json.loads(row["config"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "started_at": row["started_at"], "finished_at": row["finished_at"],
            "last_error": row["last_error"], "inventory_snapshot_id": row["inventory_snapshot_id"],
            "truncated": json.loads(row["truncated"]), "out_of_scope": json.loads(row["out_of_scope"]),
            "source_failures": json.loads(row["source_failures"]), "query_count": row["query_count"],
            "elapsed_seconds": float(row["elapsed_seconds"]),
            "counts": self._counts(db, row["id"]), "flags": json.loads(row["flags"]),
        }

    def run(self, run_id: str) -> dict[str, Any] | None:
        """{"id","status","label","config": RunConfig.to_dict(),"created_at","updated_at","started_at","finished_at",
        "last_error","inventory_snapshot_id","truncated": [Truncation dicts],"out_of_scope": {reason: n},
        "source_failures": {source: n},"query_count": int,"elapsed_seconds": float,
        "counts": {"tasks_pending","tasks_done","assets","findings","coverage_checked","coverage_no_record",
                   "queue_known","queue_new","queue_unexplained","queue_third_party"},"flags":[str]}"""
        with self._tx() as db:
            row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            return self._run_dict(db, row) if row else None

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Newest first, same shape as run()."""
        limit = max(1, min(int(limit), 500))
        with self._tx() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
            return [self._run_dict(db, row) for row in rows]

    def status(self, run_id: str) -> str | None:
        """Cheap status lookup (no counts)."""
        with self._tx() as db:
            row = db.execute("SELECT status FROM runs WHERE id=?", (run_id,)).fetchone()
            return row["status"] if row else None

    def run_config(self, run_id: str) -> RunConfig | None:
        """The run's configuration as a RunConfig record."""
        with self._tx() as db:
            row = db.execute("SELECT config FROM runs WHERE id=?", (run_id,)).fetchone()
            return _config_from_dict(json.loads(row["config"])) if row else None

    def set_status(self, run_id: str, status: RunStatus, error: str | None = None) -> None:
        """Also sets started_at on first 'running' and finished_at on 'complete'/'failed'.
        last_error is set when ``error`` is given and cleared when the run goes back to 'queued'/'running'."""
        if status not in RUN_STATUSES:
            raise ValueError(f"Unknown run status {status!r}")
        now = utc_now()
        with self._tx(write=True) as db:
            row = db.execute("SELECT started_at FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            sets = ["status=?", "updated_at=?"]
            args: list[Any] = [status, now]
            if status == "running" and row["started_at"] is None:
                sets.append("started_at=?")
                args.append(now)
            if status in ("complete", "failed"):
                sets.append("finished_at=?")
                args.append(now)
            if error is not None:
                sets.append("last_error=?")
                args.append(error)
            elif status in ("queued", "running"):
                sets.append("last_error=NULL")
            db.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id=?", (*args, run_id))

    def add_run_flag(self, run_id: str, flag: str) -> None:
        with self._tx(write=True) as db:
            row = db.execute("SELECT flags FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            flags = json.loads(row["flags"])
            if flag not in flags:
                flags.append(flag)
                db.execute("UPDATE runs SET flags=?, updated_at=? WHERE id=?", (_dumps(flags), utc_now(), run_id))

    def add_elapsed(self, run_id: str, seconds: float) -> None:
        with self._tx(write=True) as db:
            db.execute("UPDATE runs SET elapsed_seconds=elapsed_seconds+?, updated_at=? WHERE id=?",
                       (max(0.0, float(seconds)), utc_now(), run_id))

    def next_queued_run(self) -> str | None:
        """Oldest run with status 'queued'."""
        with self._tx() as db:
            row = db.execute("SELECT id FROM runs WHERE status='queued' ORDER BY seq LIMIT 1").fetchone()
            return row["id"] if row else None

    # ---- tasks (work queue)
    @staticmethod
    def _insert_tasks(db: sqlite3.Connection, run_id: str,
                      tasks: Iterable[tuple[str, str, str, int, str | None]]) -> int:
        inserted = 0
        for source, query, seed_id, depth, from_asset_id in tasks:
            cur = db.execute("INSERT OR IGNORE INTO tasks(run_id, source, query, seed_id, depth, from_asset_id) "
                             "VALUES (?,?,?,?,?,?)", (run_id, source, query, seed_id, int(depth), from_asset_id))
            inserted += cur.rowcount
        return inserted

    def add_tasks(self, run_id: str, tasks: Iterable[tuple[str, str, str, int, str | None]]) -> int:
        """Insert (source, query, seed_id, depth, from_asset_id) as 'pending'; duplicates of an existing
        (run, source, query) are ignored, whatever their seed (a query reached from two seeds runs once; the first
        seed wins). Returns number inserted."""
        with self._tx(write=True) as db:
            return self._insert_tasks(db, run_id, tasks)

    def pending_tasks(self, run_id: str, limit: int) -> list[dict[str, Any]]:
        """Oldest pending first: {"id","source","query","seed_id","depth","from_asset_id"}."""
        with self._tx() as db:
            rows = db.execute("SELECT id, source, query, seed_id, depth, from_asset_id FROM tasks "
                              "WHERE run_id=? AND status='pending' ORDER BY id LIMIT ?",
                              (run_id, max(0, int(limit)))).fetchall()
            return [dict(row) for row in rows]

    def has_tasks(self, run_id: str) -> bool:
        with self._tx() as db:
            return db.execute("SELECT 1 FROM tasks WHERE run_id=? LIMIT 1", (run_id,)).fetchone() is not None

    def skip_pending_tasks(self, run_id: str) -> int:
        """Mark all pending tasks 'skipped'; return how many."""
        with self._tx(write=True) as db:
            return db.execute("UPDATE tasks SET status='skipped' WHERE run_id=? AND status='pending'",
                              (run_id,)).rowcount

    def commit_batch(self, run_id: str, *, done_task_ids: Iterable[int], evidence: Iterable[Evidence],
                     assets: Iterable[tuple[Asset, str, int, str | None]],
                     relationships: Iterable[Relationship], new_tasks: Iterable[tuple[str, str, str, int, str | None]],
                     coverage: Iterable[tuple[str, str, str, str]], queries: int,
                     source_failures: dict[str, int], out_of_scope: dict[str, int],
                     truncations: Iterable[Truncation]) -> None:
        """One transaction. assets: (asset, seed_id, depth, path_relationship_id) inserted only if the asset id is new
        for the run (first path wins). relationships: upsert by id, merging evidence_ids (dedup, order kept).
        coverage: (ip, source, status, retrieved_at). Counters add. Truncations merge by limit (omitted adds)."""
        with self._tx(write=True) as db:
            run = db.execute("SELECT source_failures, out_of_scope, truncated FROM runs WHERE id=?",
                             (run_id,)).fetchone()
            if run is None:
                raise KeyError(run_id)

            for task_id in done_task_ids:
                db.execute("UPDATE tasks SET status='done' WHERE id=? AND run_id=?", (int(task_id), run_id))

            ev_seq = db.execute("SELECT COALESCE(MAX(seq), 0) FROM evidence WHERE run_id=?", (run_id,)).fetchone()[0]
            for ev in evidence:
                ev_seq += 1
                db.execute("INSERT OR IGNORE INTO evidence(run_id, id, seq, source, query, source_url, raw_sha256, "
                           "observed_at, valid_from, valid_to, source_record_id, ok, data) "
                           "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (run_id, ev.id, ev_seq, ev.source, ev.query, ev.source_url, ev.raw_sha256, ev.observed_at,
                            ev.valid_from, ev.valid_to, ev.source_record_id, int(_evidence_ok(ev)),
                            _dumps(ev.data)))

            asset_seq = db.execute("SELECT COALESCE(MAX(seq), 0) FROM assets WHERE run_id=?",
                                   (run_id,)).fetchone()[0]
            for asset, seed_id, depth, path_rel in assets:
                asset_seq += 1
                db.execute("INSERT OR IGNORE INTO assets(run_id, asset_id, type, value, seed_id, depth, "
                           "path_relationship_id, seq) VALUES (?,?,?,?,?,?,?,?)",
                           (run_id, asset.id, asset.type, asset.value, seed_id, int(depth), path_rel, asset_seq))

            rel_seq = db.execute("SELECT COALESCE(MAX(seq), 0) FROM relationships WHERE run_id=?",
                                 (run_id,)).fetchone()[0]
            for rel in relationships:
                existing = db.execute("SELECT evidence_ids FROM relationships WHERE run_id=? AND id=?",
                                      (run_id, rel.id)).fetchone()
                if existing is None:
                    rel_seq += 1
                    merged = list(dict.fromkeys(rel.evidence_ids))
                    db.execute("INSERT INTO relationships(run_id, id, seq, subject_id, predicate, object_id, "
                               "evidence_ids, seed_id, depth) VALUES (?,?,?,?,?,?,?,?,?)",
                               (run_id, rel.id, rel_seq, rel.subject_id, rel.predicate, rel.object_id,
                                _dumps(merged), rel.seed_id, int(rel.depth)))
                else:
                    merged = list(dict.fromkeys([*json.loads(existing["evidence_ids"]), *rel.evidence_ids]))
                    db.execute("UPDATE relationships SET evidence_ids=? WHERE run_id=? AND id=?",
                               (_dumps(merged), run_id, rel.id))

            self._insert_tasks(db, run_id, new_tasks)

            for ip, source, status, retrieved_at in coverage:
                db.execute("INSERT INTO coverage(run_id, ip_int, ip, source, status, retrieved_at) "
                           "VALUES (?,?,?,?,?,?) ON CONFLICT(run_id, ip_int, source) "
                           "DO UPDATE SET status=excluded.status, retrieved_at=excluded.retrieved_at",
                           (run_id, _ip_int(ip), ip, source, status, retrieved_at))

            failures = json.loads(run["source_failures"])
            for key, n in source_failures.items():
                failures[key] = failures.get(key, 0) + int(n)
            scope = json.loads(run["out_of_scope"])
            for key, n in out_of_scope.items():
                scope[key] = scope.get(key, 0) + int(n)
            truncated = json.loads(run["truncated"])
            by_limit = {t["limit"]: t for t in truncated}
            for t in truncations:
                if t.limit in by_limit:
                    by_limit[t.limit]["omitted"] += int(t.omitted)
                    by_limit[t.limit]["detail"] = t.detail
                else:
                    entry = t.to_dict()
                    truncated.append(entry)
                    by_limit[t.limit] = entry
            db.execute("UPDATE runs SET query_count=query_count+?, source_failures=?, out_of_scope=?, truncated=?, "
                       "updated_at=? WHERE id=?",
                       (int(queries), _dumps(failures), _dumps(scope), _dumps(truncated), utc_now(), run_id))

    # ---- discovery reads
    def assets(self, run_id: str) -> list[dict[str, Any]]:
        """{"asset": Asset, "seed_id", "depth", "path_relationship_id"} in insertion order."""
        with self._tx() as db:
            rows = db.execute("SELECT asset_id, type, value, seed_id, depth, path_relationship_id FROM assets "
                              "WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        return [{"asset": Asset(id=r["asset_id"], type=r["type"], value=r["value"]), "seed_id": r["seed_id"],
                 "depth": r["depth"], "path_relationship_id": r["path_relationship_id"]} for r in rows]

    def asset_count(self, run_id: str, type_: str) -> int:
        with self._tx() as db:
            return db.execute("SELECT COUNT(*) FROM assets WHERE run_id=? AND type=?", (run_id, type_)).fetchone()[0]

    def has_asset(self, run_id: str, asset_id: str) -> bool:
        with self._tx() as db:
            return db.execute("SELECT 1 FROM assets WHERE run_id=? AND asset_id=?",
                              (run_id, asset_id)).fetchone() is not None

    def evidence(self, run_id: str, ids: Iterable[str] | None = None) -> list[Evidence]:
        """All evidence in insertion order, or only the given ids (in the order given, unknown ids skipped)."""
        with self._tx() as db:
            if ids is None:
                rows = db.execute("SELECT * FROM evidence WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
                return [_evidence_from_row(r) for r in rows]
            wanted = list(dict.fromkeys(ids))
            found: dict[str, Evidence] = {}
            for start in range(0, len(wanted), 500):
                chunk = wanted[start:start + 500]
                marks = ",".join("?" * len(chunk))
                for r in db.execute(f"SELECT * FROM evidence WHERE run_id=? AND id IN ({marks})", (run_id, *chunk)):
                    found[r["id"]] = _evidence_from_row(r)
            return [found[i] for i in wanted if i in found]

    def relationships(self, run_id: str) -> list[Relationship]:
        with self._tx() as db:
            rows = db.execute("SELECT * FROM relationships WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        return [_relationship_from_row(r) for r in rows]

    def coverage(self, run_id: str) -> Iterator[dict[str, Any]]:
        """{"ip","source","status","retrieved_at"} ordered by ip numerically (then source)."""
        with self._tx() as db:
            rows = db.execute("SELECT ip, source, status, retrieved_at FROM coverage WHERE run_id=? "
                              "ORDER BY ip_int, source", (run_id,)).fetchall()
        return iter([dict(r) for r in rows])

    def rdap_cache(self, run_id: str) -> list[Evidence]:
        """All rdap evidence with status ok for the run (engine reuses by cidr)."""
        with self._tx() as db:
            rows = db.execute("SELECT * FROM evidence WHERE run_id=? AND source='rdap' AND ok=1 ORDER BY seq",
                              (run_id,)).fetchall()
        return [_evidence_from_row(r) for r in rows]

    # ---- assessment
    def save_assessment(self, run_id: str, snapshot_id: str, assertions: list[Assertion],
                        matches: list[InventoryMatch], findings: list[Finding]) -> None:
        """Replace any previous assessment for the run atomically and set run.inventory_snapshot_id."""
        with self._tx(write=True) as db:
            if db.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone() is None:
                raise KeyError(run_id)
            for table in ("assertions", "inventory_matches", "findings"):
                db.execute(f"DELETE FROM {table} WHERE run_id=?", (run_id,))
            db.executemany(
                "INSERT INTO assertions(run_id, id, seq, asset_id, dimension, assessment, data) VALUES (?,?,?,?,?,?,?)",
                [(run_id, a.id, i, a.asset_id, a.dimension, a.assessment, _dumps(a.to_dict()))
                 for i, a in enumerate(assertions)])
            db.executemany(
                "INSERT INTO inventory_matches(run_id, asset_id, seq, snapshot_id, entry_id, rule, status) "
                "VALUES (?,?,?,?,?,?,?)",
                [(run_id, m.asset_id, i, m.snapshot_id, m.entry_id, m.rule, m.status) for i, m in enumerate(matches)])
            db.executemany(
                "INSERT INTO findings(run_id, id, asset_id, asset_type, value, queue, queue_order, rank, flags, data) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(run_id, f.id, f.asset_id, f.asset_type, f.value, f.queue, QUEUE_ORDER.get(f.queue, 99),
                  float(f.rank), "|" + "|".join(f.flags) + "|", _dumps(f.to_dict())) for f in findings])
            db.execute("UPDATE runs SET inventory_snapshot_id=?, updated_at=? WHERE id=?",
                       (snapshot_id, utc_now(), run_id))

    def assertions(self, run_id: str) -> list[Assertion]:
        with self._tx() as db:
            rows = db.execute("SELECT data FROM assertions WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        return [_assertion_from_dict(json.loads(r["data"])) for r in rows]

    def inventory_matches(self, run_id: str) -> list[InventoryMatch]:
        with self._tx() as db:
            rows = db.execute("SELECT asset_id, snapshot_id, entry_id, rule, status FROM inventory_matches "
                              "WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        return [InventoryMatch(**dict(r)) for r in rows]

    def findings(self, run_id: str, *, queue: str | None = None, asset_type: str | None = None,
                 search: str | None = None, flag: str | None = None, sort: str = "rank",
                 offset: int = 0, limit: int = 100) -> tuple[list[Finding], int]:
        """Filtered page + total count. sort: "rank" (desc, then value) | "value" | "queue"."""
        if sort not in _FINDING_SORTS:
            raise ValueError(f"Unknown sort {sort!r}; expected one of {', '.join(_FINDING_SORTS)}")
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        where = ["run_id=?"]
        args: list[Any] = [run_id]
        if queue:
            where.append("queue=?")
            args.append(queue)
        if asset_type:
            where.append("asset_type=?")
            args.append(asset_type)
        if search:
            where.append("lower(value) LIKE ? ESCAPE '\\'")
            args.append(f"%{_like_escape(search.lower())}%")
        if flag:
            where.append("instr(flags, ?) > 0")
            args.append(f"|{flag}|")
        clause = " AND ".join(where)
        with self._tx() as db:
            total = db.execute(f"SELECT COUNT(*) FROM findings WHERE {clause}", args).fetchone()[0]
            rows = db.execute(f"SELECT data FROM findings WHERE {clause} ORDER BY {_FINDING_SORTS[sort]} "
                              "LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
        return [_finding_from_dict(json.loads(r["data"])) for r in rows], total

    def finding(self, run_id: str, finding_id: str) -> Finding | None:
        with self._tx() as db:
            row = db.execute("SELECT data FROM findings WHERE run_id=? AND id=?", (run_id, finding_id)).fetchone()
        return _finding_from_dict(json.loads(row["data"])) if row else None

    # ---- inventory
    def save_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Insert (idempotent by id: same content re-imported creates no duplicate but becomes current again)."""
        with self._tx(write=True) as db:
            touched = db.execute("SELECT COALESCE(MAX(touched), 0) + 1 FROM inventory_snapshots").fetchone()[0]
            exists = db.execute("SELECT 1 FROM inventory_snapshots WHERE id=?", (snapshot.id,)).fetchone()
            if exists:
                db.execute("UPDATE inventory_snapshots SET touched=? WHERE id=?", (touched, snapshot.id))
                return
            db.execute("INSERT INTO inventory_snapshots(id, as_of, imported_at, label, entry_count, touched) "
                       "VALUES (?,?,?,?,?,?)", (snapshot.id, snapshot.as_of, snapshot.imported_at, snapshot.label,
                                                len(snapshot.entries), touched))
            db.executemany("INSERT INTO inventory_entries(snapshot_id, position, id, kind, value, label) "
                           "VALUES (?,?,?,?,?,?)",
                           [(snapshot.id, i, e.id, e.kind, e.value, e.label) for i, e in enumerate(snapshot.entries)])

    def _load_snapshot(self, db: sqlite3.Connection, row: sqlite3.Row | None) -> InventorySnapshot | None:
        if row is None:
            return None
        entries = tuple(InventoryEntry(id=e["id"], kind=e["kind"], value=e["value"], label=e["label"])
                        for e in db.execute("SELECT id, kind, value, label FROM inventory_entries "
                                            "WHERE snapshot_id=? ORDER BY position", (row["id"],)))
        return InventorySnapshot(id=row["id"], as_of=row["as_of"], imported_at=row["imported_at"],
                                 label=row["label"], entries=entries)

    def current_snapshot(self) -> InventorySnapshot | None:
        with self._tx() as db:
            row = db.execute("SELECT * FROM inventory_snapshots ORDER BY touched DESC LIMIT 1").fetchone()
            return self._load_snapshot(db, row)

    def snapshot(self, snapshot_id: str) -> InventorySnapshot | None:
        with self._tx() as db:
            row = db.execute("SELECT * FROM inventory_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            return self._load_snapshot(db, row)

    def snapshots(self) -> list[dict[str, Any]]:
        """Newest first: {"id","as_of","imported_at","label","entry_count","current": bool}."""
        with self._tx() as db:
            rows = db.execute("SELECT * FROM inventory_snapshots ORDER BY touched DESC").fetchall()
        return [{"id": r["id"], "as_of": r["as_of"], "imported_at": r["imported_at"], "label": r["label"],
                 "entry_count": r["entry_count"], "current": i == 0} for i, r in enumerate(rows)]
