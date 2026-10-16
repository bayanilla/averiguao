"""SQLite persistence for runs, tasks, discovery records, assessments and inventory snapshots.

Owner: store/runner agent. Single file database, WAL mode, one short-lived connection per call (thread-safe).
All JSON-ish fields are stored as JSON text and returned as Python objects / contract records.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Iterator

from .contracts import (Assertion, Asset, Evidence, Finding, InventoryMatch, InventorySnapshot, Relationship,
                        RunConfig, RunStatus, Truncation)

DEFAULT_DB = Path(__file__).resolve().parent.parent / ".averiguao" / "averiguao.sqlite3"


class Store:
    def __init__(self, path: Path = DEFAULT_DB):
        """Create schema if missing. Any run left 'running' or 'pausing' by a crash becomes 'paused' with
        last_error 'Interrupted by restart.'; its 'running' tasks go back to 'pending'."""
        raise NotImplementedError

    # ---- runs
    def create_run(self, config: RunConfig) -> str:
        """Insert a run with status 'queued'; return run id (uuid4 hex)."""
        raise NotImplementedError

    def run(self, run_id: str) -> dict[str, Any] | None:
        """{"id","status","label","config": RunConfig.to_dict(),"created_at","updated_at","started_at","finished_at",
        "last_error","inventory_snapshot_id","truncated": [Truncation dicts],"out_of_scope": {reason: n},
        "source_failures": {source: n},"query_count": int,"elapsed_seconds": float,
        "counts": {"tasks_pending","tasks_done","assets","findings","coverage_checked","coverage_no_record",
                   "queue_known","queue_new","queue_unexplained","queue_third_party"},"flags":[str]}"""
        raise NotImplementedError

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Newest first, same shape as run()."""
        raise NotImplementedError

    def set_status(self, run_id: str, status: RunStatus, error: str | None = None) -> None:
        """Also sets started_at on first 'running' and finished_at on 'complete'/'failed'."""
        raise NotImplementedError

    def add_run_flag(self, run_id: str, flag: str) -> None: raise NotImplementedError

    def add_elapsed(self, run_id: str, seconds: float) -> None: raise NotImplementedError

    def next_queued_run(self) -> str | None:
        """Oldest run with status 'queued'."""
        raise NotImplementedError

    # ---- tasks (work queue)
    def add_tasks(self, run_id: str, tasks: Iterable[tuple[str, str, str, int, str | None]]) -> int:
        """Insert (source, query, seed_id, depth, from_asset_id) as 'pending'; duplicates of an existing
        (run, source, query, seed_id) are ignored. Returns number inserted."""
        raise NotImplementedError

    def pending_tasks(self, run_id: str, limit: int) -> list[dict[str, Any]]:
        """Oldest pending first: {"id","source","query","seed_id","depth","from_asset_id"}."""
        raise NotImplementedError

    def has_tasks(self, run_id: str) -> bool: raise NotImplementedError

    def skip_pending_tasks(self, run_id: str) -> int:
        """Mark all pending tasks 'skipped'; return how many."""
        raise NotImplementedError

    def commit_batch(self, run_id: str, *, done_task_ids: Iterable[int], evidence: Iterable[Evidence],
                     assets: Iterable[tuple[Asset, str, int, str | None]],
                     relationships: Iterable[Relationship], new_tasks: Iterable[tuple[str, str, str, int, str | None]],
                     coverage: Iterable[tuple[str, str, str, str]], queries: int,
                     source_failures: dict[str, int], out_of_scope: dict[str, int],
                     truncations: Iterable[Truncation]) -> None:
        """One transaction. assets: (asset, seed_id, depth, path_relationship_id) inserted only if the asset id is new
        for the run (first path wins). relationships: upsert by id, merging evidence_ids (dedup, order kept).
        coverage: (ip, source, status, retrieved_at). Counters add. Truncations merge by limit (omitted adds)."""
        raise NotImplementedError

    # ---- discovery reads
    def assets(self, run_id: str) -> list[dict[str, Any]]:
        """{"asset": Asset, "seed_id", "depth", "path_relationship_id"} in insertion order."""
        raise NotImplementedError

    def asset_count(self, run_id: str, type_: str) -> int: raise NotImplementedError

    def has_asset(self, run_id: str, asset_id: str) -> bool: raise NotImplementedError

    def evidence(self, run_id: str, ids: Iterable[str] | None = None) -> list[Evidence]: raise NotImplementedError

    def relationships(self, run_id: str) -> list[Relationship]: raise NotImplementedError

    def coverage(self, run_id: str) -> Iterator[dict[str, Any]]:
        """{"ip","source","status","retrieved_at"} ordered by ip numerically."""
        raise NotImplementedError

    def rdap_cache(self, run_id: str) -> list[Evidence]:
        """All rdap evidence with status ok for the run (engine reuses by cidr)."""
        raise NotImplementedError

    # ---- assessment
    def save_assessment(self, run_id: str, snapshot_id: str, assertions: list[Assertion],
                        matches: list[InventoryMatch], findings: list[Finding]) -> None:
        """Replace any previous assessment for the run atomically and set run.inventory_snapshot_id."""
        raise NotImplementedError

    def assertions(self, run_id: str) -> list[Assertion]: raise NotImplementedError

    def findings(self, run_id: str, *, queue: str | None = None, asset_type: str | None = None,
                 search: str | None = None, flag: str | None = None, sort: str = "rank",
                 offset: int = 0, limit: int = 100) -> tuple[list[Finding], int]:
        """Filtered page + total count. sort: "rank" (desc, then value) | "value" | "queue"."""
        raise NotImplementedError

    def finding(self, run_id: str, finding_id: str) -> Finding | None: raise NotImplementedError

    # ---- inventory
    def save_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Insert (idempotent by id: same content re-imported creates no duplicate but becomes current again)."""
        raise NotImplementedError

    def current_snapshot(self) -> InventorySnapshot | None: raise NotImplementedError

    def snapshot(self, snapshot_id: str) -> InventorySnapshot | None: raise NotImplementedError

    def snapshots(self) -> list[dict[str, Any]]:
        """Newest first: {"id","as_of","imported_at","label","entry_count","current": bool}."""
        raise NotImplementedError
