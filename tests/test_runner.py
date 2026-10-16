import tempfile
import threading
import time
import unittest
from pathlib import Path

from averiguao_core.contracts import RunConfig, Seed
from averiguao_core.runner import Runner
from averiguao_core.store import Store

TIMEOUT = 2.0


def wait_for(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    raise AssertionError("condition not reached in time")


class FakeEngine:
    """execute() blocks until the test releases the run (or stop is set when honour_stop is on).

    Each call records whether stop was set at its checkpoint; it returns "stopped" if so, else "done"."""

    def __init__(self):
        self.lock = threading.Lock()
        self.calls: list[str] = []
        self.started: dict[str, threading.Event] = {}
        self.release: dict[str, threading.Event] = {}
        self.checkpoint: dict[str, threading.Event] = {}
        self.honour_stop = True
        self.raise_for: dict[str, Exception] = {}
        self.assessed: list[str] = []
        self.assess_error: Exception | None = None
        self.kwargs: list[dict] = []

    def _event(self, table, run_id):
        with self.lock:
            return table.setdefault(run_id, threading.Event())

    def execute(self, store, run_id, connectors, stop, **kwargs):
        with self.lock:
            self.calls.append(run_id)
            self.kwargs.append(kwargs)
        self._event(self.started, run_id).set()
        if run_id in self.raise_for:
            raise self.raise_for[run_id]
        release = self._event(self.release, run_id)
        while not release.is_set():
            if self.honour_stop and stop.is_set():
                break
            release.wait(0.005)
        checkpoint = self._event(self.checkpoint, run_id)
        stopped = stop.is_set()
        checkpoint.set()
        return "stopped" if stopped else "done"

    def assess(self, store, run_id):
        if self.assess_error:
            raise self.assess_error
        self.assessed.append(run_id)


def config(label):
    return RunConfig(seeds=(Seed("seed:1", "domain", "example.com", "T-1", "1"),), org_names=(), label=label)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "db.sqlite3")
        self.engine = FakeEngine()
        self.runner = Runner(self.store, lambda: {}, workers=3, batch_size=7,
                             execute=self.engine.execute, assess=self.engine.assess)

    def tearDown(self):
        for ev in list(self.engine.release.values()):
            ev.set()
        self.runner.shutdown(timeout=2)
        self.tmp.cleanup()

    def new_run(self, label="r"):
        run_id = self.store.create_run(config(label))
        self.runner.submit(run_id)
        return run_id

    def status(self, run_id):
        return self.store.run(run_id)["status"]

    def release(self, run_id):
        self.engine._event(self.engine.release, run_id).set()

    def started(self, run_id):
        return self.engine._event(self.engine.started, run_id).is_set()

    def test_complete_and_parameters(self):
        run_id = self.new_run()
        wait_for(lambda: self.started(run_id))
        self.assertEqual(self.runner.active_run(), run_id)
        self.assertEqual(self.status(run_id), "running")
        self.release(run_id)
        wait_for(lambda: self.status(run_id) == "complete")
        self.assertEqual(self.engine.assessed, [run_id])
        self.assertEqual(self.engine.kwargs[0], {"workers": 3, "batch_size": 7})
        run = self.store.run(run_id)
        self.assertIsNotNone(run["finished_at"])
        self.assertGreater(run["elapsed_seconds"], 0)
        wait_for(lambda: self.runner.active_run() is None)

    def test_fifo_queue_and_auto_start(self):
        first, second, third = self.new_run("1"), self.new_run("2"), self.new_run("3")
        wait_for(lambda: self.started(first))
        self.assertEqual((self.status(second), self.status(third)), ("queued", "queued"))
        self.release(first)
        wait_for(lambda: self.started(second))
        self.assertEqual(self.status(first), "complete")
        self.assertEqual(self.status(third), "queued")
        self.release(second)
        self.release(third)
        wait_for(lambda: self.status(third) == "complete")
        self.assertEqual(self.engine.calls, [first, second, third])

    def test_submit_starts_oldest_queued_and_rejects_non_queued(self):
        older = self.store.create_run(config("older"))
        newer = self.store.create_run(config("newer"))
        self.runner.submit(newer)
        wait_for(lambda: self.started(older))
        self.assertEqual(self.status(newer), "queued")
        with self.assertRaises(ValueError):
            self.runner.submit(older)
        with self.assertRaises(ValueError):
            self.runner.submit("missing")

    def test_pause_then_resume_while_pausing_continues(self):
        self.engine.honour_stop = False  # the engine is busy with its batch; it only sees stop at the checkpoint
        run_id = self.new_run()
        wait_for(lambda: self.started(run_id))
        self.assertEqual(self.runner.pause(run_id), "pausing")
        self.assertEqual(self.status(run_id), "pausing")
        self.assertEqual(self.runner.resume(run_id), "running")  # no 409 window
        self.assertEqual(self.status(run_id), "running")
        self.release(run_id)
        wait_for(lambda: self.status(run_id) == "complete")
        self.assertEqual(self.engine.calls, [run_id])

    def test_resume_after_engine_saw_stop_reexecutes_same_run(self):
        self.engine.honour_stop = False
        run_id = self.new_run()
        other = self.new_run("other")
        wait_for(lambda: self.started(run_id))
        # Hold the runner lock so the worker cannot finalize 'paused' between the engine returning and resume().
        with self.runner._lock:
            self.assertEqual(self.runner.pause(run_id), "pausing")
            self.release(run_id)
            wait_for(lambda: self.engine._event(self.engine.checkpoint, run_id).is_set())
            self.assertEqual(self.runner.resume(run_id), "running")
        wait_for(lambda: self.status(run_id) == "complete")
        self.assertEqual(self.engine.calls[:2], [run_id, run_id])  # continued the same run immediately
        self.release(other)
        wait_for(lambda: self.status(other) == "complete")

    def test_pause_running_then_resume_paused(self):
        run_id = self.new_run()
        wait_for(lambda: self.started(run_id))
        self.assertEqual(self.runner.pause(run_id), "pausing")
        wait_for(lambda: self.status(run_id) == "paused")
        wait_for(lambda: self.runner.active_run() is None)
        with self.assertRaises(ValueError):
            self.runner.pause(run_id)
        self.assertEqual(self.runner.resume(run_id), "running")  # idle runner: queued and started at once
        wait_for(lambda: len(self.engine.calls) == 2)
        self.release(run_id)
        wait_for(lambda: self.status(run_id) == "complete")
        with self.assertRaises(ValueError):
            self.runner.resume(run_id)

    def test_pause_queued_and_resume_paused_while_busy(self):
        first, second = self.new_run("1"), self.new_run("2")
        wait_for(lambda: self.started(first))
        self.assertEqual(self.runner.pause(second), "paused")
        self.assertEqual(self.runner.resume(second), "queued")  # busy: waits its turn
        self.assertEqual(self.status(second), "queued")
        self.release(first)
        self.release(second)
        wait_for(lambda: self.status(second) == "complete")

    def test_paused_run_does_not_auto_start(self):
        first, second, third = self.new_run("1"), self.new_run("2"), self.new_run("3")
        wait_for(lambda: self.started(first))
        self.runner.pause(second)
        self.release(first)
        wait_for(lambda: self.started(third))
        self.assertEqual(self.status(second), "paused")
        self.release(third)
        wait_for(lambda: self.status(third) == "complete")

    def test_paused_frees_runner_for_next(self):
        first, second = self.new_run("1"), self.new_run("2")
        wait_for(lambda: self.started(first))
        self.runner.pause(first)
        wait_for(lambda: self.started(second))
        self.assertEqual(self.status(first), "paused")
        self.assertEqual(self.runner.active_run(), second)

    def test_execute_failure(self):
        bad = self.store.create_run(config("bad"))
        good = self.store.create_run(config("good"))
        self.engine.raise_for[bad] = RuntimeError("x" * 500)
        self.runner.submit(bad)
        wait_for(lambda: self.status(bad) == "failed")
        run = self.store.run(bad)
        self.assertTrue(run["last_error"].startswith("RuntimeError: xxx"))
        self.assertEqual(len(run["last_error"]), 300)
        self.assertNotIn("Traceback", run["last_error"])
        self.assertIsNotNone(run["finished_at"])
        wait_for(lambda: self.started(good))  # next queued run starts after a failure
        self.release(good)
        wait_for(lambda: self.status(good) == "complete")

    def test_assess_failure(self):
        self.engine.assess_error = KeyError("snapshot")
        run_id = self.new_run()
        self.release(run_id)
        wait_for(lambda: self.status(run_id) == "failed")
        self.assertEqual(self.store.run(run_id)["last_error"], "KeyError: 'snapshot'")

    def test_reassess(self):
        run_id = self.new_run()
        with self.assertRaises(ValueError):
            self.runner.reassess(run_id)
        self.release(run_id)
        wait_for(lambda: self.status(run_id) == "complete")
        self.runner.reassess(run_id)
        self.assertEqual(self.engine.assessed, [run_id, run_id])
        self.assertEqual(self.status(run_id), "complete")
        with self.assertRaises(ValueError):
            self.runner.reassess("missing")

    def test_shutdown_leaves_paused_and_starts_nothing(self):
        first, second = self.new_run("1"), self.new_run("2")
        wait_for(lambda: self.started(first))
        self.runner.shutdown(timeout=2)
        self.assertEqual(self.status(first), "paused")
        self.assertEqual(self.status(second), "queued")
        self.assertIsNone(self.runner.active_run())

    def test_invalid_transitions(self):
        with self.assertRaises(ValueError):
            self.runner.pause("missing")
        with self.assertRaises(ValueError):
            self.runner.resume("missing")
        run_id = self.store.create_run(config("q"))
        self.store.set_status(run_id, "failed", "x")
        with self.assertRaises(ValueError):
            self.runner.pause(run_id)
        with self.assertRaises(ValueError):
            self.runner.resume(run_id)


if __name__ == "__main__":
    unittest.main()
