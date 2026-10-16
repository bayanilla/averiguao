"""Run queue and lifecycle. Owner: store/runner agent.

States: queued -> running -> (pausing -> paused) -> running ... -> complete | failed.
One run executes at a time; when it ends, the oldest queued run starts automatically.
"""

from __future__ import annotations

from typing import Callable

from .contracts import Connector, SourceName
from .store import Store


class Runner:
    def __init__(self, store: Store, connectors: Callable[[], dict[SourceName, Connector]], *,
                 workers: int = 8, batch_size: int = 64,
                 execute: Callable[..., str] | None = None, assess: Callable[[Store, str], None] | None = None):
        """execute(store, run_id, connectors, stop_event, workers=, batch_size=) -> "done" | "stopped" runs discovery
        (default: engine.execute). assess(store, run_id) computes findings (default: attribution.assess_run).
        After execute returns "done": assess, then status 'complete'. "stopped": status 'paused'.
        Any exception: status 'failed' with a short message (exception type and message, no traceback)."""
        raise NotImplementedError

    def submit(self, run_id: str) -> None:
        """Run is 'queued' in the store; start it now if idle."""
        raise NotImplementedError

    def pause(self, run_id: str) -> str:
        """running -> pausing (worker stops after its current batch, then paused). queued -> paused.
        Returns the new status. Raises ValueError if the state does not allow it."""
        raise NotImplementedError

    def resume(self, run_id: str) -> str:
        """pausing -> running (cancel the pending pause; no 409 window). paused -> queued (starts if idle).
        Returns the new status. Raises ValueError if the state does not allow it."""
        raise NotImplementedError

    def reassess(self, run_id: str) -> None:
        """Recompute findings for a complete run against the current inventory snapshot. ValueError if not complete."""
        raise NotImplementedError

    def active_run(self) -> str | None: raise NotImplementedError

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop the active run (it becomes paused) and wait for the worker."""
        raise NotImplementedError
