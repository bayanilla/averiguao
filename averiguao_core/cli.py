"""Command line: `serve` (default) starts the local UI; `run` executes one run headless and writes reports."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import reports
from .contracts import VERSION
from .store import DEFAULT_DB

SOURCES = ("ct", "dns", "rdap", "internetdb")
MAX_RATE = 50.0
TERMINAL = {"complete", "failed"}


def _rate(text: str) -> tuple[str, float]:
    source, sep, value = text.partition("=")
    source = source.strip().lower()
    if not sep or source not in SOURCES:
        raise argparse.ArgumentTypeError(f"expected SOURCE=N with SOURCE one of {', '.join(SOURCES)}")
    try:
        rate = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"rate for {source} is not a number") from None
    if not 0 < rate <= MAX_RATE:  # also rejects nan
        raise argparse.ArgumentTypeError(f"rate for {source} must be > 0 and <= {MAX_RATE:g} requests per second")
    return source, rate


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 0-65535")
    return port


def _workers(text: str) -> int:
    try:
        workers = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("workers must be an integer") from None
    if not 1 <= workers <= 32:
        raise argparse.ArgumentTypeError("workers must be 1-32")
    return workers


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workers", type=_workers, default=8, help="parallel source calls per batch (1-32, default 8)")
    parser.add_argument("--rate", type=_rate, action="append", default=[], metavar="SOURCE=N",
                        help="requests per second for one source (ct, dns, rdap, internetdb; 0 < N <= 50); repeatable")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DB.parent,
                        help="directory for the database (default .averiguao next to averiguao.py)")
    parser.add_argument("--demo", action="store_true",
                        help="use the built-in synthetic world (no network) and a separate demo database")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="averiguao.py", description="Múcaro | Averiguao: passive discovery of "
                                     "public infrastructure missing from an approved inventory.")
    parser.add_argument("--version", action="version", version=f"Averiguao {VERSION}")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="start the local web UI (default)")
    serve.add_argument("--port", type=_port, default=8767, help="port on 127.0.0.1 (default 8767; 0 picks a free one)")
    _common(serve)
    run = sub.add_parser("run", help="run one configuration headless and write JSON, CSV and Markdown reports")
    run.add_argument("--config", type=Path, required=True, help="run configuration JSON (same shape as the API)")
    run.add_argument("--inventory", type=Path, help="inventory CSV to import as the current snapshot first")
    run.add_argument("--inventory-label", default="", help="label for the imported inventory snapshot")
    run.add_argument("--as-of", default=None, help="as-of time for the imported inventory")
    run.add_argument("--out", type=Path, default=Path("."), help="directory for the reports (default: current)")
    _common(run)
    return parser


def _setup(args: argparse.Namespace) -> tuple[Any, Callable[[], dict], dict[str, Any] | None]:
    """Store, connector factory and (demo only) the demo config."""
    from .store import Store
    data_dir: Path = args.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    rates = dict(args.rate)
    if args.demo:
        from .connectors import fake
        from .scope import parse_inventory
        store = Store(data_dir / "demo.sqlite3")
        snapshot = parse_inventory(fake.DEMO_INVENTORY_CSV, label="Demo inventory", as_of=None)
        if store.current_snapshot() is None or store.current_snapshot().id != snapshot.id:
            store.save_snapshot(snapshot)
        return store, _demo_factory(fake), dict(fake.DEMO_CONFIG)
    from .connectors import live_connectors
    store = Store(data_dir / "averiguao.sqlite3")
    # One set of connectors for the whole process, so rate spacing and any source-imposed cooldown survive
    # pause/resume and back-to-back runs.
    connectors = live_connectors(rates)
    return store, (lambda: connectors), None


def _demo_factory(fake: Any) -> Callable[[], dict]:
    def factory() -> dict:
        world = fake.demo_world()
        if isinstance(world, dict):
            return world
        connectors = getattr(world, "connectors", None)
        return connectors() if callable(connectors) else connectors
    return factory


def _runner(store: Any, factory: Callable[[], dict], workers: int) -> Any:
    from .runner import Runner
    return Runner(store, factory, workers=workers)


def serve(args: argparse.Namespace) -> int:
    from .server import make_server
    store, factory, demo_config = _setup(args)
    runner = _runner(store, factory, args.workers)
    queued = store.next_queued_run()  # runs queued by a previous process do not start by themselves
    if queued:
        runner.submit(queued)
    demo_expected = None
    if args.demo:
        from .connectors import fake
        demo_expected = {key: {"queue": queue, "why": why}
                         for key, (queue, why) in getattr(fake, "DEMO_EXPECTED", {}).items()}
    server = make_server(store, runner, port=args.port, demo=args.demo, demo_config=demo_config,
                         demo_expected=demo_expected)
    port = server.server_address[1]
    note = " (demo: synthetic world, no network)" if args.demo else ""
    print(f"Múcaro | Averiguao: http://127.0.0.1:{port}/{note}", flush=True)
    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)  # treat a polite kill like Ctrl-C: pause the active run first
    if signal.getsignal(signal.SIGINT) is signal.SIG_IGN:
        signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping; the active run will be paused.", file=sys.stderr, flush=True)
    finally:
        runner.shutdown()
        server.server_close()
    return 0


def _progress(run: dict[str, Any]) -> str:
    counts = run.get("counts") or {}
    return (f"\r{run['status']}: tasks {counts.get('tasks_done', 0)} done / {counts.get('tasks_pending', 0)} pending, "
            f"{run.get('query_count', 0)} queries, {counts.get('assets', 0)} assets   ")


def run_headless(args: argparse.Namespace) -> int:
    from .scope import ScopeError, parse_inventory, parse_run_config
    try:
        body = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(body, dict):
            raise ValueError("configuration must be a JSON object")
        body = body.get("config", body)
        config = parse_run_config(body, allow_documentation_ranges=True) if args.demo else parse_run_config(body)
        inventory = None
        if args.inventory:
            inventory = parse_inventory(args.inventory.read_text(encoding="utf-8"), label=args.inventory_label,
                                        as_of=args.as_of)
        args.out.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError, ScopeError) as exc:  # json.JSONDecodeError is a ValueError
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    store, factory, _ = _setup(args)
    if inventory is not None:
        store.save_snapshot(inventory)
    runner = _runner(store, factory, args.workers)
    run_id = store.create_run(config)
    runner.submit(run_id)
    interactive = sys.stderr.isatty()
    run = store.run(run_id)
    try:
        while run is not None and run["status"] not in TERMINAL:
            if run["status"] == "paused" and runner.active_run() is None:
                break
            if interactive:
                print(_progress(run), end="", file=sys.stderr, flush=True)
            time.sleep(0.25)
            run = store.run(run_id)
    except KeyboardInterrupt:
        print("\nInterrupted; pausing the run (resume it from the UI).", file=sys.stderr)
        runner.shutdown()
        return 130
    runner.shutdown()
    run = store.run(run_id)
    print(_progress(run).strip(), file=sys.stderr)
    if run["status"] != "complete":
        print(f"Run {run_id} ended {run['status']}: {run.get('last_error') or 'no detail'}", file=sys.stderr)
        return 3
    for ext, fn in (("json", reports.json_report), ("csv", reports.csv_report), ("md", reports.markdown_report)):
        path = args.out / reports.report_filename(run_id, ext)
        with open(path, "wb") as handle:
            for chunk in fn(store, run_id):
                handle.write(chunk)
        print(f"Wrote {path}", file=sys.stderr)
    if run.get("truncated"):
        print("Warning: the run was truncated by a limit; see the reports.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in {"serve", "run", "-h", "--help", "--version"}:
        argv = ["serve", *argv]
    args = build_parser().parse_args(argv)
    code = run_headless(args) if args.command == "run" else serve(args)
    sys.exit(code)
