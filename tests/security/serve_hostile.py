"""Serve a completed hostile-data run for xss_probe.mjs. Prints `READY http://127.0.0.1:<port>/?token=<token> <run_id>`.
Run from the repository root: python3 -m tests.security.serve_hostile"""

from __future__ import annotations

import tempfile
import threading

from tests.security._hostile import TOKEN, build_hostile_run, start_server


def main() -> None:
    tmp = tempfile.TemporaryDirectory(prefix="averiguao-xss-")
    store, run_id = build_hostile_run(tmp.name)
    httpd = start_server(store)
    print(f"READY http://127.0.0.1:{httpd.server_address[1]}/?token={TOKEN} {run_id}", flush=True)
    try:
        threading.Event().wait()  # start_server already serves on a daemon thread
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        tmp.cleanup()


if __name__ == "__main__":
    main()
