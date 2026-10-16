"""Local, passive InternetDB inventory review. Python 3.10+; no dependencies."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import sqlite3
import ssl
import threading
import time
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / ".oifd" / "oifd.sqlite3"
WEB = ROOT / "web"
MAX_BODY = 1_048_576
MAX_INVENTORY_ROWS = 10_000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_public_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Enter one valid public IPv4 address or CIDR range.") from exc
    if not isinstance(network, ipaddress.IPv4Network) or not network.is_global:
        raise ValueError("InternetDB input must be a public IPv4 address or range.")
    return network


def parse_inventory(lines: str) -> list[tuple[str, int, int, str]]:
    result = []
    seen = set()
    for number, row in enumerate(csv.reader(io.StringIO(lines)), 1):
        if not row or not any(cell.strip() for cell in row):
            continue
        if number == 1 and row[0].strip().lower() in {"ip", "ip_or_cidr", "cidr", "network"}:
            continue
        if len(row) > 2:
            raise ValueError(f"Inventory row {number}: use IP_or_CIDR,label.")
        network = parse_public_network(row[0])
        label = row[1].strip() if len(row) == 2 else ""
        key = str(network)
        if key not in seen:
            result.append((key, int(network.network_address), int(network.broadcast_address), label[:200]))
            seen.add(key)
        if len(result) > MAX_INVENTORY_ROWS:
            raise ValueError("Inventory exceeds the 10,000-row limit.")
    return result


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, seed_cidr TEXT NOT NULL, total INTEGER NOT NULL,
                    next_offset INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
                    found INTEGER NOT NULL DEFAULT 0, empty INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS observations (
                    job_id TEXT NOT NULL, ip_int INTEGER NOT NULL, ip TEXT NOT NULL,
                    status TEXT NOT NULL, payload TEXT, retrieved_at TEXT NOT NULL,
                    PRIMARY KEY (job_id, ip_int), FOREIGN KEY (job_id) REFERENCES jobs(id)
                );
                CREATE INDEX IF NOT EXISTS observations_by_job ON observations(job_id, ip_int);
                CREATE TABLE IF NOT EXISTS inventory (
                    cidr TEXT PRIMARY KEY, start_ip INTEGER NOT NULL,
                    end_ip INTEGER NOT NULL, label TEXT NOT NULL
                );
            """)
            db.execute("UPDATE jobs SET status='paused', last_error='Interrupted by restart.' WHERE status='running'")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def create_job(self, network: ipaddress.IPv4Network) -> dict:
        job_id = uuid.uuid4().hex
        now = utc_now()
        with self.connect() as db:
            db.execute("INSERT INTO jobs (id,seed_cidr,total,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                       (job_id, str(network), network.num_addresses, "queued", now, now))
        return self.job(job_id)

    def job(self, job_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def jobs(self) -> list[dict]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 30")]

    def status(self, job_id: str, status: str, error: str | None = None):
        with self.connect() as db:
            db.execute("UPDATE jobs SET status=?,updated_at=?,last_error=? WHERE id=?",
                       (status, utc_now(), error, job_id))

    def commit_batch(self, job_id: str, end_offset: int, rows: list[tuple]):
        found = sum(row[2] == "found" for row in rows)
        empty = sum(row[2] == "empty" for row in rows)
        errors = sum(row[2] == "error" for row in rows)
        with self.connect() as db:
            db.executemany("INSERT OR REPLACE INTO observations (job_id,ip_int,ip,status,payload,retrieved_at) "
                           "VALUES (?,?,?,?,?,?)",
                           [(job_id, ip_int, ip, status, json.dumps(payload) if payload else None, fetched)
                            for ip_int, ip, status, payload, fetched in rows if status != "empty"])
            db.execute("UPDATE jobs SET next_offset=?,found=found+?,empty=empty+?,errors=errors+?,"
                       "updated_at=?,last_error=NULL WHERE id=?",
                       (end_offset, found, empty, errors, utc_now(), job_id))

    def replace_inventory(self, entries: list[tuple]):
        with self.connect() as db:
            db.execute("DELETE FROM inventory")
            db.executemany("INSERT INTO inventory VALUES (?,?,?,?)", entries)

    def inventory(self) -> list[dict]:
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM inventory ORDER BY start_ip")]

    def results(self, job_id: str, offset: int = 0, limit: int = 100) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM observations WHERE job_id=? ORDER BY ip_int LIMIT ? OFFSET ?",
                              (job_id, limit, offset)).fetchall()
            inventory = [dict(row) for row in db.execute("SELECT * FROM inventory")]
        matcher = InventoryMatcher(inventory)
        return [self._result(dict(row), matcher) for row in rows]

    def iter_results(self, job_id: str):
        with self.connect() as db:
            matcher = InventoryMatcher([dict(row) for row in db.execute("SELECT * FROM inventory")])
            for row in db.execute("SELECT * FROM observations WHERE job_id=? ORDER BY ip_int", (job_id,)):
                yield self._result(dict(row), matcher)

    def _result(self, row: dict, matcher: "InventoryMatcher") -> dict:
        ip_int = row.pop("ip_int")
        row["payload"] = json.loads(row["payload"]) if row["payload"] else None
        row["source"] = "Shodan InternetDB"
        row["source_url"] = f"https://internetdb.shodan.io/{row['ip']}"
        row["source_observed_at"] = None  # InternetDB does not report a per-IP scan time.
        match = matcher.match(ip_int)
        row["inventory_match"] = match
        row["inventory_status"] = "known" if match else "unaccounted"
        return row


class InventoryMatcher:
    """Longest-prefix inventory matching with a fixed number of hash lookups."""

    def __init__(self, entries: list[dict]):
        self.by_prefix = {}
        lengths = set()
        for entry in entries:
            network = ipaddress.IPv4Network(entry["cidr"])
            self.by_prefix[(int(network.network_address), network.prefixlen)] = {
                "cidr": entry["cidr"], "label": entry["label"]
            }
            lengths.add(network.prefixlen)
        self.lengths = sorted(lengths, reverse=True)

    def match(self, ip_int: int) -> dict | None:
        for length in self.lengths:
            mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF if length else 0
            found = self.by_prefix.get((ip_int & mask, length))
            if found:
                return found
        return None


class RateLimited(Exception):
    def __init__(self, seconds: float):
        self.seconds = seconds


def retry_after(value: str | None) -> float:
    if not value:
        return 30.0
    try:
        return max(1.0, min(float(value), 3600.0))
    except ValueError:
        try:
            delta = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
            return max(1.0, min(delta, 3600.0))
        except (TypeError, ValueError, OverflowError):
            return 30.0


def fetch_internetdb(ip: str) -> tuple[str, dict | None]:
    # The hostname is fixed; an input IP cannot select an arbitrary destination.
    request = Request(f"https://internetdb.shodan.io/{ip}", headers={"User-Agent": "OIFD/0.1"})
    # Python.org macOS builds may lack their own CA bundle; use the OS bundle when present.
    system_ca = Path("/etc/ssl/cert.pem")
    if not ssl.get_default_verify_paths().cafile and system_ca.is_file():
        context = ssl.create_default_context(cafile=str(system_ca))
    else:
        context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=12, context=context) as response:
            raw = response.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("InternetDB response too large")
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("ip") != ip:
            raise ValueError("Unexpected InternetDB response")
        payload = {"_response_sha256": hashlib.sha256(raw).hexdigest()}
        for key in ("ports", "hostnames", "cpes", "tags", "vulns"):
            values = data.get(key, [])
            payload[key] = values[:1000] if isinstance(values, list) else []
        return "found", payload
    except HTTPError as exc:
        try:
            if exc.code == 404:
                return "empty", None
            if exc.code == 429:
                raise RateLimited(retry_after(exc.headers.get("Retry-After"))) from exc
            raise
        finally:
            exc.close()


class RateGate:
    def __init__(self, rate: float):
        self.interval = 1.0 / rate
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.cooldown_until = 0.0

    def acquire(self, stop: threading.Event):
        while True:
            if stop.is_set():
                raise InterruptedError
            with self.lock:
                now = time.monotonic()
                when = max(self.next_at, self.cooldown_until)
                if now >= when:
                    self.next_at = now + self.interval
                    return
                wait = min(when - now, 0.5)
            stop.wait(wait)

    def cooldown(self, seconds: float):
        with self.lock:
            self.cooldown_until = max(self.cooldown_until, time.monotonic() + seconds)


class Runner:
    def __init__(self, store: Store, *, rate: float = 50, workers: int = 8,
                 batch_size: int = 256, fetcher=fetch_internetdb):
        self.store = store
        self.rate = RateGate(rate)
        self.workers = workers
        self.batch_size = batch_size
        self.fetcher = fetcher
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()

    def start(self, job_id: str) -> bool:
        job = self.store.job(job_id)
        if not job or job["status"] not in {"queued", "paused"}:
            return False
        with self.lock:
            if self.thread and self.thread.is_alive():
                return False
            self.stop = threading.Event()
            self.store.status(job_id, "running")
            self.thread = threading.Thread(target=self._run, args=(job_id, self.stop), daemon=True)
            self.thread.start()
            return True

    def pause(self, job_id: str) -> bool:
        job = self.store.job(job_id)
        if not job or job["status"] != "running":
            return False
        self.stop.set()
        return True

    def _lookup(self, ip: str, stop: threading.Event) -> tuple[str, dict | None]:
        for attempt in range(5):
            self.rate.acquire(stop)
            try:
                return self.fetcher(ip)
            except RateLimited as exc:
                self.rate.cooldown(exc.seconds)
            except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
                if attempt == 4:
                    return "error", {"message": type(exc).__name__}
                if stop.wait(min(2 ** attempt, 16)):
                    raise InterruptedError
        return "error", {"message": "Rate limit retries exhausted"}

    def _run(self, job_id: str, stop: threading.Event):
        try:
            job = self.store.job(job_id)
            network = ipaddress.IPv4Network(job["seed_cidr"])
            cursor = job["next_offset"]
            while cursor < job["total"]:
                if stop.is_set():
                    self.store.status(job_id, "paused")
                    return
                end = min(cursor + self.batch_size, job["total"])
                rows = []
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    futures = {}
                    for offset in range(cursor, end):
                        ip_int = int(network.network_address) + offset
                        ip = str(ipaddress.IPv4Address(ip_int))
                        futures[pool.submit(self._lookup, ip, stop)] = (ip_int, ip)
                    for future in as_completed(futures):
                        ip_int, ip = futures[future]
                        try:
                            status, payload = future.result()
                        except InterruptedError:
                            stop.set()
                            continue
                        rows.append((ip_int, ip, status, payload, utc_now()))
                if stop.is_set():
                    self.store.status(job_id, "paused")
                    return
                errors = sum(row[2] == "error" for row in rows)
                if errors > max(5, len(rows) // 10):
                    self.store.status(job_id, "paused", "Too many source errors; retry this batch later.")
                    return
                self.store.commit_batch(job_id, end, rows)
                cursor = end
            self.store.status(job_id, "complete")
        except Exception as exc:
            self.store.status(job_id, "paused", f"Job stopped: {type(exc).__name__}")


def safe_csv(value) -> str:
    text = str(value)
    return "'" + text if text and text[0] in "=+-@" else text


class Handler(BaseHTTPRequestHandler):
    store: Store
    runner: Runner

    def log_message(self, format, *args):
        pass  # Inputs and query results are not written to the HTTP log.

    def _allowed(self) -> bool:
        host = self.headers.get("Host", "")
        if host not in {f"127.0.0.1:{self.server.server_port}",
                        f"localhost:{self.server.server_port}"}:
            return False
        origin = self.headers.get("Origin")
        return not origin or origin in {f"http://127.0.0.1:{self.server.server_port}",
                                        f"http://localhost:{self.server.server_port}"}

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value):
        self._send(status, json.dumps(value).encode(), "application/json; charset=utf-8")

    def _body(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > MAX_BODY or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ValueError("Expected a JSON body no larger than 1 MiB.")
        value = json.loads(self.rfile.read(size))
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object.")
        return value

    def do_GET(self):
        if not self._allowed():
            return self._json(403, {"error": "Local origin required."})
        path = urlparse(self.path).path
        if path in {"/", "/app.js", "/style.css", "/themes.css", "/mucaro-mark.svg"}:
            file = WEB / ("index.html" if path == "/" else path[1:])
            mime = "text/html" if path == "/" else "text/javascript" if path.endswith(".js") else "image/svg+xml" if path.endswith(".svg") else "text/css"
            return self._send(200, file.read_bytes(), mime + "; charset=utf-8")
        if path == "/api/jobs":
            return self._json(200, {"jobs": self.store.jobs()})
        if path == "/api/inventory":
            return self._json(200, {"entries": self.store.inventory()})
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
            job = self.store.job(parts[2])
            if not job:
                return self._json(404, {"error": "Job not found."})
            if len(parts) == 3:
                return self._json(200, job)
            if parts[3] == "results":
                query = parse_qs(urlparse(self.path).query)
                try:
                    offset = max(0, int(query.get("offset", ["0"])[0]))
                    limit = min(200, max(1, int(query.get("limit", ["100"])[0])))
                except ValueError:
                    return self._json(400, {"error": "Invalid pagination."})
                return self._json(200, {"results": self.store.results(job["id"], offset, limit)})
            if parts[3] == "export.csv":
                return self._export_csv(job)
            if parts[3] == "export.json":
                return self._export_json(job)
        return self._json(404, {"error": "Not found."})

    def do_POST(self):
        if not self._allowed():
            return self._json(403, {"error": "Local origin required."})
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/preview":
                network = parse_public_network(body.get("seed", ""))
                return self._json(200, {"cidr": str(network), "addresses": network.num_addresses,
                                        "note": "InternetDB is queried once per IP; results are historical observations."})
            if path == "/api/inventory":
                entries = parse_inventory(body.get("csv", ""))
                self.store.replace_inventory(entries)
                return self._json(200, {"count": len(entries)})
            if path == "/api/jobs":
                network = parse_public_network(body.get("seed", ""))
                job = self.store.create_job(network)
                if not self.runner.start(job["id"]):
                    self.store.status(job["id"], "paused", "Another job is running.")
                return self._json(201, self.store.job(job["id"]))
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "jobs"]:
                if parts[3] == "pause" and self.runner.pause(parts[2]):
                    return self._json(202, {"status": "pausing"})
                if parts[3] == "resume" and self.runner.start(parts[2]):
                    return self._json(202, {"status": "running"})
                return self._json(409, {"error": "Job state does not allow this action."})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(404, {"error": "Not found."})

    def _export_csv(self, job):
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f"attachment; filename=oifd-{job['id'][:8]}.csv")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["seed_cidr", "ip", "status", "inventory_status", "inventory_match", "ports",
                         "hostnames", "cpes", "tags", "vulns", "retrieved_at", "source_observed_at",
                         "source", "source_url", "response_sha256"])
        self.wfile.write(buffer.getvalue().encode()); buffer.seek(0); buffer.truncate(0)
        for row in self.store.iter_results(job["id"]):
            data = row["payload"] or {}
            writer.writerow([job["seed_cidr"], row["ip"], row["status"], row["inventory_status"],
                             row["inventory_match"]["cidr"] if row["inventory_match"] else "",
                             *[safe_csv(json.dumps(data.get(key, []))) for key in
                               ("ports", "hostnames", "cpes", "tags", "vulns")],
                             row["retrieved_at"], "", row["source"], row["source_url"],
                             data.get("_response_sha256", "")])
            self.wfile.write(buffer.getvalue().encode()); buffer.seek(0); buffer.truncate(0)

    def _export_json(self, job):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f"attachment; filename=oifd-{job['id'][:8]}.json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(json.dumps({"job": job, "inventory": self.store.inventory()})[:-1].encode())
        self.wfile.write(b',"results":[')
        first = True
        for row in self.store.iter_results(job["id"]):
            self.wfile.write((b"" if first else b",") + json.dumps(row).encode())
            first = False
        self.wfile.write(b"]}")


def main():
    parser = argparse.ArgumentParser(description="Local passive IP footprint review")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--rate", type=float, default=50, help="Maximum InternetDB requests per second (default 50)")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 < args.rate <= 1000 or not 1 <= args.workers <= 32:
        parser.error("Port, rate, or worker count is outside the supported range.")
    store = Store()
    runner = Runner(store, rate=args.rate, workers=args.workers)
    handler = type("OIFDHandler", (Handler,), {"store": store, "runner": runner})
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
        print(f"Múcaro | Averiguao: http://127.0.0.1:{args.port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
