"""Run queue and lifecycle. Owner: store/runner agent.

States: queued -> running -> (pausing -> paused) -> running ... -> complete | failed.
Cancel: running/pausing -> cancelling -> cancelled (after the current batch); queued/paused -> cancelled at once.
A cancelled run keeps what it collected, skips the rest (recorded as a "cancelled" truncation) and is assessed.
One run executes at a time; when it ends, the oldest queued run starts automatically.

The store holds the status (single source of truth). The runner holds only the active run id, its stop Event and
its worker thread; ``self._lock`` serializes every state transition so a pause/resume can never race the worker's
decision to finish.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from .contracts import Connector, SourceName, Truncation
from .store import Store

MAX_ERROR_CHARS = 300


def _error_message(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]


class Runner:
    def __init__(self, store: Store, connectors: Callable[[], dict[SourceName, Connector]], *,
                 workers: int = 8, batch_size: int = 64,
                 execute: Callable[..., str] | None = None, assess: Callable[[Store, str], None] | None = None):
        """execute(store, run_id, connectors, stop_event, workers=, batch_size=) -> "done" | "stopped" runs discovery
        (default: engine.execute). assess(store, run_id) computes findings (default: attribution.assess_run).
        After execute returns "done": assess, then status 'complete'. "stopped": status 'paused'.
        Any exception: status 'failed' with a short message (exception type and message, no traceback)."""
        if execute is None:
            from .engine import execute as default_execute
            execute = default_execute
        if assess is None:
            from .attribution import assess_run
            assess = assess_run
        self.store = store
        self.connectors = connectors
        self.workers = workers
        self.batch_size = batch_size
        self._execute = execute
        self._assess = assess
        self._lock = threading.RLock()
        self._active: str | None = None
        self._stop: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._closing = False

    # ------------------------------------------------------------------ public API
    def submit(self, run_id: str) -> None:
        """Run is 'queued' in the store; start it now if idle (the oldest queued run starts first, FIFO)."""
        with self._lock:
            status = self.store.status(run_id)
            if status is None:
                raise ValueError(f"Unknown run {run_id}")
            if status != "queued":
                raise ValueError(f"Cannot submit run in status '{status}'; only 'queued' runs can be submitted")
            self._start_next_locked()

    def pause(self, run_id: str) -> str:
        """running -> pausing (worker stops after its current batch, then paused). queued -> paused.
        Returns the new status. Raises ValueError if the state does not allow it."""
        with self._lock:
            status = self.store.status(run_id)
            if status is None:
                raise ValueError(f"Unknown run {run_id}")
            if status == "running" and run_id == self._active and self._stop is not None:
                self.store.set_status(run_id, "pausing")
                self._stop.set()
                return "pausing"
            if status == "running":
                # Not executed by this runner (stale state): nothing to stop, so it is paused right away.
                self.store.set_status(run_id, "paused")
                return "paused"
            if status == "queued":
                self.store.set_status(run_id, "paused")
                return "paused"
            raise ValueError(f"Cannot pause run in status '{status}'; only 'running' or 'queued' runs can be paused")

    def resume(self, run_id: str) -> str:
        """pausing -> running (cancel the pending pause; no 409 window). paused -> queued (starts if idle).
        Returns the new status (for a paused run: 'running' if it started at once, else 'queued').
        Raises ValueError if the state does not allow it."""
        with self._lock:
            status = self.store.status(run_id)
            if status is None:
                raise ValueError(f"Unknown run {run_id}")
            if status == "pausing" and run_id == self._active and self._stop is not None:
                self.store.set_status(run_id, "running")
                self._stop.clear()
                return "running"
            if status in ("paused", "pausing"):
                # "pausing" without an active worker is stale; treat it like paused.
                self.store.set_status(run_id, "queued")
                self._start_next_locked()
                return self.store.status(run_id) or "queued"
            raise ValueError(f"Cannot resume run in status '{status}'; only 'paused' or 'pausing' runs can be resumed")

    def cancel(self, run_id: str) -> str:
        """running/pausing -> cancelling (the worker stops after its current batch, then the run is finalized as
        cancelled). queued/paused -> cancelled immediately. Cancelling again is a no-op. Returns the new status.
        Raises ValueError for complete, failed or cancelled runs."""
        with self._lock:
            status = self.store.status(run_id)
            if status is None:
                raise ValueError(f"Unknown run {run_id}")
            if status == "cancelling":
                return status
            if status in ("running", "pausing") and run_id == self._active and self._stop is not None:
                self.store.set_status(run_id, "cancelling")
                self._stop.set()
                return "cancelling"
            if status in ("queued", "paused", "running", "pausing"):  # running/pausing here: stale, no worker
                self.store.set_status(run_id, "cancelled", self._finalize_cancel(run_id))
                return "cancelled"
            raise ValueError(f"Cannot cancel run in status '{status}'; only queued, running or paused runs can be "
                             f"cancelled")

    def reassess(self, run_id: str) -> None:
        """Recompute findings for a complete or cancelled run against the current inventory snapshot. ValueError
        otherwise. The status is kept; an exception from assess propagates and leaves the previous assessment intact."""
        status = self.store.status(run_id)
        if status is None:
            raise ValueError(f"Unknown run {run_id}")
        if status not in ("complete", "cancelled"):
            raise ValueError(f"Cannot reassess run in status '{status}'; only complete or cancelled runs can be "
                             f"reassessed")
        self._assess(self.store, run_id)

    def active_run(self) -> str | None:
        with self._lock:
            return self._active

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop the active run (it becomes paused) and wait for the worker. No queued run starts afterwards."""
        with self._lock:
            self._closing = True
            thread = self._thread
            if self._stop is not None:
                self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    # ------------------------------------------------------------------ internals
    def _start_next_locked(self) -> None:
        if self._closing or self._active is not None:
            return
        run_id = self.store.next_queued_run()
        if run_id is None:
            return
        self.store.set_status(run_id, "running")
        stop = threading.Event()
        thread = threading.Thread(target=self._work, args=(run_id, stop), name=f"averiguao-run-{run_id[:8]}",
                                  daemon=True)
        self._active, self._stop, self._thread = run_id, stop, thread
        thread.start()

    def _finish_locked(self, run_id: str, status: str, error: str | None = None) -> None:
        """Record the final status of this execution and release the runner, then start the next queued run."""
        try:
            self.store.set_status(run_id, status, error)  # type: ignore[arg-type]
        finally:
            self._active, self._stop, self._thread = None, None, None
            self._start_next_locked()

    def _work(self, run_id: str, stop: threading.Event) -> None:
        try:
            while True:
                started = time.monotonic()
                try:
                    result = self._execute(self.store, run_id, self.connectors(), stop,
                                           workers=self.workers, batch_size=self.batch_size)
                except Exception as exc:
                    self._add_elapsed(run_id, started)
                    with self._lock:
                        self._finish_locked(run_id, "failed", _error_message(exc))
                    return
                self._add_elapsed(run_id, started)

                if result == "done":
                    try:
                        self._assess(self.store, run_id)
                    except Exception as exc:
                        with self._lock:
                            self._finish_locked(run_id, "failed", _error_message(exc))
                        return
                    with self._lock:
                        self._finish_locked(run_id, "complete")
                    return

                if result != "stopped":
                    with self._lock:
                        self._finish_locked(run_id, "failed", f"ValueError: execute returned {result!r}")
                    return

                with self._lock:
                    status = self.store.status(run_id)
                    # A resume while pausing put the status back to 'running' and cleared the event: keep going.
                    if not self._closing and not stop.is_set() and status == "running":
                        continue
                    if status != "cancelling":
                        self._finish_locked(run_id, "paused")
                        return
                error = self._finalize_cancel(run_id)  # outside the lock: assessment can take a moment
                with self._lock:
                    self._finish_locked(run_id, "cancelled", error)
                return
        except BaseException as exc:  # last resort: never leave the runner stuck with an active run
            with self._lock:
                if self._active == run_id:
                    self._finish_locked(run_id, "failed", _error_message(exc))
            raise

    def _finalize_cancel(self, run_id: str) -> str | None:
        """Skip the remaining work, record it as a 'cancelled' truncation and assess what was collected.
        Returns an error message if the assessment failed (the run is still cancelled), else None."""
        skipped = self.store.skip_pending_tasks(run_id)
        self.store.commit_batch(run_id, done_task_ids=[], evidence=[], assets=[], relationships=[], new_tasks=[],
                                coverage=[], queries=0, source_failures={}, out_of_scope={},
                                truncations=[Truncation(limit="cancelled", omitted=skipped,
                                                        detail="Cancelled by the analyst; remaining work skipped.")])
        try:
            self._assess(self.store, run_id)
        except Exception as exc:
            return f"Cancelled, but findings could not be computed ({_error_message(exc)}). Use Reassess."
        return None

    def _add_elapsed(self, run_id: str, started: float) -> None:
        try:
            self.store.add_elapsed(run_id, time.monotonic() - started)
        except Exception:
            pass
