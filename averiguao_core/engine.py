"""Bounded discovery engine (docs/RULES.md section 2). Owner: graph/attribution agent."""

from __future__ import annotations

import threading

from .contracts import Connector, SourceName
from .store import Store


def execute(store: Store, run_id: str, connectors: dict[SourceName, Connector], stop: threading.Event, *,
            workers: int = 8, batch_size: int = 64) -> str:
    """Seed initial tasks if the run has none yet, then process pending tasks in batches until none remain
    ("done"), `stop` is set ("stopped", after committing the current batch), or a limit ends the run
    ("done", with truncation recorded). Resumable: calling again continues from the persisted queue."""
    raise NotImplementedError
