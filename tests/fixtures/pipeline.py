"""Run the Stage 1 pipeline end to end through public interfaces only (no runner thread, no network)."""

from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any, Mapping

from averiguao_core import attribution, engine, scope
from averiguao_core.store import Store


def build_config(config_body: Mapping[str, Any], limits: Mapping[str, Any] | None = None,
                 match_rules: Mapping[str, Any] | None = None):
    body = copy.deepcopy(dict(config_body))
    if limits:
        body["limits"] = {**body.get("limits", {}), **limits}
    if match_rules:
        body["match_rules"] = {**body.get("match_rules", {}), **match_rules}
    return scope.parse_run_config(body, allow_documentation_ranges=True)


def prepare_run(config_body: Mapping[str, Any], inventory_csv: str | None = None, *, tmpdir: str,
                limits: Mapping[str, Any] | None = None, match_rules: Mapping[str, Any] | None = None,
                db_name: str = "test.sqlite3") -> tuple[Store, str]:
    """Create the store, save the inventory snapshot (if any) and a queued run; nothing executed yet."""
    config = build_config(config_body, limits, match_rules)
    store = Store(Path(tmpdir) / db_name)
    if inventory_csv is not None:
        store.save_snapshot(scope.parse_inventory(inventory_csv, label="test inventory"))
    run_id = store.create_run(config)
    return store, run_id


def finish_run(store: Store, run_id: str) -> None:
    attribution.assess_run(store, run_id)
    store.set_status(run_id, "complete")


def run_pipeline(connectors: Mapping[str, Any], config_body: Mapping[str, Any], inventory_csv: str | None = None, *,
                 tmpdir: str, limits: Mapping[str, Any] | None = None,
                 match_rules: Mapping[str, Any] | None = None, db_name: str = "test.sqlite3") -> tuple[Store, str]:
    store, run_id = prepare_run(config_body, inventory_csv, tmpdir=tmpdir, limits=limits, match_rules=match_rules,
                                db_name=db_name)
    store.set_status(run_id, "running")
    outcome = engine.execute(store, run_id, dict(connectors), threading.Event(), workers=4, batch_size=16)
    if outcome != "done":
        raise AssertionError(f"engine.execute returned {outcome!r}, expected 'done'")
    finish_run(store, run_id)
    return store, run_id
