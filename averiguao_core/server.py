"""Local HTTP API and static UI. Owner: reports/UI agent. Binds to 127.0.0.1 only.

Security model (single local user): every API call and the UI page need the per-process access token, which
the CLI prints as part of the URL and the server turns into an HttpOnly, SameSite=Strict cookie (blocks other
local users and processes, which can reach any loopback port). The Host header must name this loopback port (blocks DNS rebinding),
an Origin header, when sent, must be this server (blocks cross-site requests), POST bodies must be
``application/json`` (forces a CORS preflight, which is never answered) and are size-capped. Responses carry
a strict CSP, nosniff and no-store. Requests are never logged: queries and inventory are sensitive.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qs, unquote, urlsplit

from . import reports
from .contracts import VERSION, Limits
from .scope import ScopeError, parse_inventory, parse_run_config
from .store import Store

WEB = Path(__file__).resolve().parent.parent / "web"
MAX_BODY = 2 * 1024 * 1024
MAX_PAGE = 200
PAGES = {"/", "/index.html"}  # the UI page itself requires the access token
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/themes.css": ("themes.css", "text/css; charset=utf-8"),
    "/mucaro-mark.svg": ("mucaro-mark.svg", "image/svg+xml"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
RUN_ID = re.compile(r"[0-9a-f]{32}")
FINDING_ID = re.compile(r"fd:(domain|hostname|ip):[A-Za-z0-9._:*\-]{1,260}")
QUEUES = {"known", "new", "unexplained", "third_party"}
ASSET_TYPES = {"domain", "hostname", "ip"}
SORTS = {"rank", "value", "queue"}
FLAG_RE = re.compile(r"[a-z_]{1,40}")
DIMENSIONS = ("ownership", "operational_control", "hosting", "service_association")
ROUGH_DOMAIN_EXPANSION = 20  # hostnames a typical domain seed yields; each costs ~3 queries (dns, rdap, internetdb)


LOCKED_PAGE = (b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Averiguao</title>"
               b"</head><body><h1>Access token required</h1><p>Open the full link that Averiguao printed in the "
               b"terminal when it started. It includes an access token, so other users and programs on this "
               b"computer cannot read your findings.</p></body></html>")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def estimate(config: Any) -> tuple[int, list[str]]:
    """Rough query estimate and warnings for a validated RunConfig."""
    limits: Limits = config.limits
    total = 0
    warnings: list[str] = []
    for seed in config.seeds:
        if seed.type == "domain":
            total += 2 + min(limits.max_hostnames, ROUGH_DOMAIN_EXPANSION) * 3
        elif seed.type == "prefix":
            addresses = ipaddress.ip_network(seed.value).num_addresses
            total += addresses + 1
            if addresses >= 1024:
                warnings.append(f"{seed.value} has {addresses:,} addresses; each gets one InternetDB query, "
                                f"so this run may take a long time.")
        else:
            total += 2
    if any(seed.type == "domain" for seed in config.seeds):
        warnings.append("Domain seeds expand through Certificate Transparency; the estimate is rough and the "
                        "real count depends on what CT returns.")
    if total > limits.max_queries:
        warnings.append(f"The estimate exceeds max_queries ({limits.max_queries:,}); the run will probably be "
                        f"truncated.")
    if not config.org_names:
        warnings.append("No organization names: IP ownership can never be supported in this run.")
    return total, warnings


class Handler(BaseHTTPRequestHandler):
    server_version = "Averiguao"
    sys_version = ""
    protocol_version = "HTTP/1.0"  # every response closes the connection; streamed exports need no length
    timeout = 20  # seconds; a stalled or slow client is dropped instead of pinning a thread
    store: Store
    runner: Any
    demo: bool = False
    demo_config: dict[str, Any] | None = None
    demo_expected: dict[str, Any] | None = None
    token: str = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # Inputs and query results are never written to the HTTP log.

    # ---------------------------------------------------------------- plumbing
    def _allowed(self) -> bool:
        port = self.server.server_address[1]
        if self.headers.get("Host", "") not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
            return False
        return self.headers.get("Sec-Fetch-Site", "same-origin") in {"same-origin", "none"}

    def _cookie_name(self) -> str:
        return f"averiguao_{self.server.server_address[1]}"  # cookies ignore ports; keep instances apart

    def _authorized(self) -> bool:
        try:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(self._cookie_name())
        except CookieError:
            return False
        return morsel is not None and hmac.compare_digest(morsel.value.encode(), self.token.encode())

    def _token_login(self, query: dict[str, list[str]]) -> bool:
        """GET /?token=... with the right token sets the session cookie and redirects to a clean URL."""
        supplied = (query.get("token") or [""])[0]
        if not supplied or not hmac.compare_digest(supplied.encode(), self.token.encode()):
            return False
        cookie = f"{self._cookie_name()}={self.token}; Path=/; HttpOnly; SameSite=Strict"
        self._headers(303, "text/plain; charset=utf-8", 0, extra={"Location": "/", "Set-Cookie": cookie})
        return True

    def _headers(self, status: int, content_type: str, length: int | None = None,
                 extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self._headers(status, content_type, len(body))
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _stream(self, filename: str, content_type: str, chunks: Iterator[bytes]) -> None:
        first = next(chunks, b"")  # errors before the first byte still become a JSON error response
        self._headers(200, content_type, extra={"Content-Disposition": f'attachment; filename="{filename}"'})
        self.wfile.write(first)
        for chunk in chunks:
            self.wfile.write(chunk)
        self.close_connection = True

    def _body(self) -> dict[str, Any]:
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise ApiError(415, "Expected Content-Type application/json.")
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(400, "Chunked request bodies are not accepted.")
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise ApiError(411, "Content-Length required.") from None
        if size > MAX_BODY:
            raise ApiError(413, f"Request body is larger than {MAX_BODY // 1048576} MiB.")
        if size <= 0:
            raise ApiError(400, "Expected a JSON object body.")
        try:
            value = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "Body is not valid JSON.") from None
        if not isinstance(value, dict):
            raise ApiError(400, "Expected a JSON object.")
        return value

    def _dispatch(self, routes: Callable[[list[str], dict[str, list[str]]], None]) -> None:
        if not self._allowed():
            return self._json(403, {"error": "Local origin required."})
        split = urlsplit(self.path)
        raw_parts = [p for p in split.path.split("/") if p]
        try:
            parts = [unquote(p, errors="strict") for p in raw_parts]
            query = parse_qs(split.query, keep_blank_values=False, max_num_fields=20)
            if parts[:1] == ["api"] and not self._authorized():
                raise ApiError(401, "Access token required: open the link Averiguao printed when it started.")
            routes(parts, query)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except ScopeError as exc:
            self._json(400, {"error": str(exc)})
        except UnicodeDecodeError:
            self._json(400, {"error": "Invalid path encoding."})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except TimeoutError:  # socket.timeout: the client stalled mid-request; drop it without a response
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the client
            try:
                self._json(500, {"error": f"Internal error: {type(exc).__name__}"})
            except OSError:
                pass

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(self._get)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(self._get)

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch(self._post)

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, {"error": "Method not allowed."})

    do_DELETE = do_PATCH = do_PUT  # noqa: N815

    # ---------------------------------------------------------------- helpers
    def _run(self, run_id: str) -> dict[str, Any]:
        if not RUN_ID.fullmatch(run_id):
            raise ApiError(404, "Run not found.")
        run = self.store.run(run_id)
        if run is None:
            raise ApiError(404, "Run not found.")
        return run

    @staticmethod
    def _int(query: dict[str, list[str]], name: str, default: int, low: int, high: int) -> int:
        raw = query.get(name, [str(default)])[0]
        if not re.fullmatch(r"\d{1,9}", raw):
            raise ApiError(400, f"{name} must be a non-negative integer.")
        return max(low, min(high, int(raw)))

    @staticmethod
    def _choice(query: dict[str, list[str]], name: str, allowed: set[str]) -> str | None:
        raw = query.get(name, [""])[0]
        if not raw:
            return None
        if raw not in allowed:
            raise ApiError(400, f"Unknown {name}: choose one of {', '.join(sorted(allowed))}.")
        return raw

    def _parse_config(self, body: dict[str, Any]):
        config = body.get("config", body)
        if not isinstance(config, dict):
            raise ApiError(400, "config must be an object.")
        if self.demo:
            return parse_run_config(config, allow_documentation_ranges=True)
        return parse_run_config(config)

    # ---------------------------------------------------------------- GET
    def _get(self, parts: list[str], query: dict[str, list[str]]) -> None:
        path = "/" + "/".join(parts)
        if path in PAGES and not self._authorized():
            if self._token_login(query):
                return None
            return self._send(401, LOCKED_PAGE, "text/html; charset=utf-8")
        if path in STATIC and (len(parts) <= 1):
            name, mime = STATIC[path]
            return self._send(200, (WEB / name).read_bytes(), mime)
        if parts[:1] != ["api"]:
            raise ApiError(404, "Not found.")
        if parts == ["api", "health"]:
            body: dict[str, Any] = {"version": VERSION, "demo": self.demo}
            if self.demo and self.demo_config is not None:
                body["demo_config"] = self.demo_config
            if self.demo and self.demo_expected is not None:
                body["demo_expected"] = self.demo_expected
            return self._json(200, body)
        if parts == ["api", "runs"]:
            return self._json(200, {"runs": self.store.runs()})
        if parts == ["api", "inventory"]:
            current = self.store.current_snapshot()
            return self._json(200, {"current": current.to_dict() if current else None,
                                    "snapshots": self.store.snapshots()})
        if len(parts) >= 3 and parts[1] == "runs":
            run = self._run(parts[2])
            rest = parts[3:]
            if not rest:
                return self._json(200, run)
            if rest == ["findings"]:
                return self._findings(run, query)
            if len(rest) == 2 and rest[0] == "findings":
                return self._finding(run, rest[1])
            if rest == ["coverage"]:
                offset = self._int(query, "offset", 0, 0, 10**9)
                limit = self._int(query, "limit", 100, 1, MAX_PAGE)
                rows, total = [], 0
                for row in self.store.coverage(run["id"]):
                    if offset <= total < offset + limit:
                        rows.append(row)
                    total += 1
                return self._json(200, {"coverage": rows, "total": total})
            exports = {
                "export.json": (reports.json_report, "json", "application/json; charset=utf-8"),
                "export.csv": (reports.csv_report, "csv", "text/csv; charset=utf-8"),
                "export.md": (reports.markdown_report, "md", "text/markdown; charset=utf-8"),
            }
            if len(rest) == 1 and rest[0] in exports:
                fn, ext, mime = exports[rest[0]]
                return self._stream(reports.report_filename(run["id"], ext), mime, iter(fn(self.store, run["id"])))
        raise ApiError(404, "Not found.")

    def _findings(self, run: dict[str, Any], query: dict[str, list[str]]) -> None:
        flag = query.get("flag", [""])[0] or None
        if flag is not None and not FLAG_RE.fullmatch(flag):
            raise ApiError(400, "Invalid flag.")
        search = query.get("q", [""])[0].strip() or None
        if search is not None and len(search) > 200:
            raise ApiError(400, "Search text is longer than 200 characters.")
        try:
            findings, total = self._query_findings(run, query, search, flag)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from None
        rows = []
        if findings:
            wanted = {i for f in findings for i in f.assertion_ids}
            by_id = {a.id: a for a in self.store.assertions(run["id"]) if a.id in wanted}
            for f in findings:
                row = f.to_dict()
                # Compact per-dimension summary so the table can show badges without one request per row.
                row["assessments"] = {by_id[i].dimension: {"assessment": by_id[i].assessment, "value": by_id[i].value}
                                      for i in f.assertion_ids if i in by_id}
                rows.append(row)
        return self._json(200, {"findings": rows, "total": total})

    def _query_findings(self, run: dict[str, Any], query: dict[str, list[str]], search: str | None,
                        flag: str | None) -> tuple[list[Any], int]:
        return self.store.findings(
            run["id"], queue=self._choice(query, "queue", QUEUES), asset_type=self._choice(query, "type", ASSET_TYPES),
            search=search, flag=flag, sort=self._choice(query, "sort", SORTS) or "rank",
            offset=self._int(query, "offset", 0, 0, 10**9), limit=self._int(query, "limit", 50, 1, MAX_PAGE))

    def _finding(self, run: dict[str, Any], finding_id: str) -> None:
        if not FINDING_ID.fullmatch(finding_id):
            raise ApiError(404, "Finding not found.")
        finding = self.store.finding(run["id"], finding_id)
        if finding is None:
            raise ApiError(404, "Finding not found.")
        wanted = set(finding.assertion_ids)
        assertions = {a.id: a for a in self.store.assertions(run["id"]) if a.id in wanted}
        relationships = {r.id: r for r in self.store.relationships(run["id"]) if r.id in set(finding.path)}
        ev_ids: list[str] = list(finding.evidence_ids)
        for rel in relationships.values():
            ev_ids.extend(i for i in rel.evidence_ids if i not in ev_ids)
        for a in assertions.values():
            ev_ids.extend(i for i in (*a.supporting_evidence_ids, *a.contradicting_evidence_ids) if i not in ev_ids)
        evidence = {e.id: e for e in self.store.evidence(run["id"], ev_ids)}
        seeds = {s["id"]: s for s in run["config"].get("seeds", [])}

        def node(node_id: str) -> dict[str, Any]:
            if node_id in seeds:
                return {"id": node_id, "type": "seed", "value": seeds[node_id]["value"],
                        "seed_type": seeds[node_id]["type"]}
            type_, _, value = node_id.partition(":")
            return {"id": node_id, "type": type_, "value": value}

        path = []
        for rel_id in finding.path:
            rel = relationships.get(rel_id)
            if rel is None:
                continue
            path.append({"relationship": rel.to_dict(), "subject": node(rel.subject_id), "object": node(rel.object_id),
                         "evidence": [evidence[i].to_dict() for i in rel.evidence_ids if i in evidence]})
        ordered = [assertions[i].to_dict() for i in finding.assertion_ids if i in assertions]
        return self._json(200, {"finding": finding.to_dict(), "assertions": ordered, "path": path,
                                "evidence": [evidence[i].to_dict() for i in ev_ids if i in evidence]})

    # ---------------------------------------------------------------- POST
    def _post(self, parts: list[str], query: dict[str, list[str]]) -> None:
        body = self._body()
        if parts == ["api", "preview"]:
            config = self._parse_config(body)
            estimated, warnings = estimate(config)
            if self.store.current_snapshot() is None:
                warnings.append("No inventory snapshot is loaded: every finding will be New, Unexplained or "
                                "Third-party until you import one and reassess.")
            return self._json(200, {"seeds": [s.to_dict() for s in config.seeds], "estimated_queries": estimated,
                                    "warnings": warnings, "config": config.to_dict()})
        if parts == ["api", "runs"]:
            config = self._parse_config(body)
            run_id = self.store.create_run(config)
            self.runner.submit(run_id)
            return self._json(201, self.store.run(run_id))
        if parts == ["api", "inventory"]:
            csv_text = body.get("csv", "")
            label = body.get("label", "") or ""
            as_of = body.get("as_of") or None
            if not isinstance(csv_text, str) or not isinstance(label, str) or not (as_of is None or isinstance(as_of, str)):
                raise ApiError(400, "csv, label and as_of must be strings.")
            if len(label) > 200:
                raise ApiError(400, "Label is longer than 200 characters.")
            snapshot = parse_inventory(csv_text, label=label.strip(), as_of=as_of)
            self.store.save_snapshot(snapshot)
            summary = {k: v for k, v in snapshot.to_dict().items() if k != "entries"}
            summary["entry_count"] = len(snapshot.entries)
            return self._json(200, {"snapshot": summary, "entry_count": len(snapshot.entries)})
        if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] in {"pause", "resume", "reassess"}:
            run = self._run(parts[2])
            try:
                if parts[3] == "pause":
                    status = self.runner.pause(run["id"])
                elif parts[3] == "resume":
                    status = self.runner.resume(run["id"])
                else:
                    self.runner.reassess(run["id"])
                    status = (self.store.run(run["id"]) or run)["status"]
            except ValueError as exc:
                raise ApiError(409, str(exc) or "Run state does not allow this action.") from None
            except Exception as exc:  # noqa: BLE001 - reassess failures leave the run complete; report why
                raise ApiError(500, "Reassessment failed.") from None
            return self._json(200, {"status": status})
        raise ApiError(404, "Not found.")


MAX_CONNECTIONS = 32


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over the cap: refuse rather than spawn another thread
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(store: Store, runner: Any, *, port: int, token: str, demo: bool = False,
                demo_config: dict[str, Any] | None = None,
                demo_expected: dict[str, Any] | None = None) -> ThreadingHTTPServer:
    """HTTP server on 127.0.0.1:port (0 picks a free port; read it from server.server_address).
    `token` (at least 32 characters, e.g. secrets.token_urlsafe(32)) gates the UI page and every API call."""
    if len(token) < 32:
        raise ValueError("The access token must be at least 32 characters.")
    handler = type("AveriguaoHandler", (Handler,), {"store": store, "runner": runner, "demo": demo, "token": token,
                                                    "demo_config": demo_config, "demo_expected": demo_expected})
    return Server(("127.0.0.1", port), handler)
