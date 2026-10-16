"""Shared HTTPS client for the source connectors (stdlib only, Python 3.10+).

Fixes over the old ``oifd.fetch_internetdb``: one verified SSL context per client (not per request),
persistent keep-alive connections per thread and host, and an identifying User-Agent.

Policy, in order of application for each ``get``:

* HTTPS only, certificate verification always on. Every host contacted, including redirect
  targets, must be in ``allowed_hosts``.
* A rate gate shared by all threads using this client spaces request starts by ``1/rate`` seconds.
  HTTP 429 sets a cooldown (``Retry-After`` seconds or HTTP date, clamped 1..3600, default 30) that
  holds back every thread, then the request is retried.
* 5xx, timeouts and connection errors are retried with exponential backoff (1, 2, 4, 8 s).
  Other statuses (2xx, 404 and other 4xx) are returned to the caller.
* Up to 3 redirects (301/302/303/307/308) are followed, only to https URLs on allowed hosts.
* Bodies are capped at ``max_bytes`` (after gzip decompression too).
* After ``max_retries`` retries, :class:`SourceError` is raised with a short reason (no URLs, no tracebacks).

Testing: ``transport`` replaces the connection factory. It is called as
``transport(host, timeout, ssl_context)`` and must return an object with the ``http.client.HTTPConnection``
methods ``request(method, path, headers=...)``, ``getresponse()`` and ``close()``. The response needs
``status``, ``getheaders()`` and ``read(amt)``. ``sleep``, ``clock`` (monotonic) and ``wall_clock``
(epoch seconds, for Retry-After dates) are injectable so tests never wait or open sockets.
There is deliberately no plain-HTTP switch.
"""

from __future__ import annotations

import email.utils
import http.client
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from ..contracts import USER_AGENT

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 3
DEFAULT_RETRY_AFTER = 30.0
_STALE_ERRORS = (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError)


class SourceError(Exception):
    """A source could not be read. ``reason`` is short and safe to store and show."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class HttpResponse:
    status: int
    body: bytes
    url: str
    headers: dict[str, str] = field(default_factory=dict)   # lower-case names


def make_ssl_context() -> ssl.SSLContext:
    # Python.org macOS builds may lack their own CA bundle; use the OS bundle when present.
    system_ca = Path("/etc/ssl/cert.pem")
    if ssl.get_default_verify_paths().cafile is None and system_ca.is_file():
        return ssl.create_default_context(cafile=str(system_ca))
    return ssl.create_default_context()


def _default_transport(host: str, timeout: float, context: ssl.SSLContext) -> Any:
    return http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)


def parse_retry_after(value: str | None, now_epoch: float) -> float:
    """Seconds to wait per a Retry-After header, clamped to 1..3600; 30 when absent or unparseable."""
    seconds = DEFAULT_RETRY_AFTER
    if value:
        value = value.strip()
        if value.isdigit():
            seconds = float(value)
        else:
            try:
                when = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError, IndexError):
                when = None
            if when is not None and when.tzinfo is not None:
                seconds = when.timestamp() - now_epoch
    return min(max(seconds, 1.0), 3600.0)


class RateGate:
    """Spaces request starts by ``1/rate`` across threads and enforces a shared cooldown."""

    def __init__(self, rate: float, *, clock: Callable[[], float], sleep: Callable[[float], None]):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.interval = 1.0 / rate
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_at = 0.0
        self._cooldown_until = 0.0

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                when = max(self._next_at, self._cooldown_until)
                if now >= when:
                    self._next_at = now + self.interval
                    return
                wait = when - now
            self._sleep(wait)

    def cooldown(self, seconds: float) -> None:
        with self._lock:
            self._cooldown_until = max(self._cooldown_until, self._clock() + seconds)


class HttpClient:
    def __init__(
        self,
        *,
        rate: float,
        allowed_hosts: set[str] | frozenset[str] | tuple[str, ...] | list[str],
        max_bytes: int,
        timeout: float = 15,
        max_retries: int = 4,
        user_agent: str = USER_AGENT,
        transport: Callable[[str, float, ssl.SSLContext], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ):
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.ssl_context = make_ssl_context()
        self._transport = transport or _default_transport
        self._sleep = sleep
        self._wall_clock = wall_clock
        self.gate = RateGate(rate, clock=clock, sleep=sleep)
        self._local = threading.local()

    # ------------------------------------------------------------------ connections

    def _pool(self) -> dict[str, list]:
        pool = getattr(self._local, "pool", None)
        if pool is None:
            pool = self._local.pool = {}
        return pool

    def _connection(self, host: str) -> tuple[Any, bool]:
        """Return (connection, reused) for this thread and host. Entry is [conn, uses]."""
        pool = self._pool()
        entry = pool.get(host)
        if entry is None:
            entry = pool[host] = [self._transport(host, self.timeout, self.ssl_context), 0]
        reused = entry[1] > 0
        entry[1] += 1
        return entry[0], reused

    def _drop(self, host: str) -> None:
        entry = self._pool().pop(host, None)
        if entry is not None:
            try:
                entry[0].close()
            except Exception:
                pass

    def close(self) -> None:
        """Close this thread's connections."""
        for host in list(self._pool()):
            self._drop(host)

    # ------------------------------------------------------------------ requests

    def _check_url(self, url: str) -> tuple[str, str]:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise SourceError("non_https_url")
        host = (parts.hostname or "").lower()
        if host not in self.allowed_hosts or parts.port not in (None, 443) or parts.username or parts.password:
            raise SourceError("host_not_allowed")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return host, path

    def _read_body(self, resp: Any) -> tuple[bytes, bool]:
        """Read up to max_bytes+1. Returns (body, too_large)."""
        chunks: list[bytes] = []
        total = 0
        limit = self.max_bytes + 1
        while total < limit:
            chunk = resp.read(limit - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), total > self.max_bytes

    def _once(self, host: str, path: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        """One request on the pooled connection; one silent reconnect if a reused connection went stale."""
        for attempt in (0, 1):
            conn, reused = self._connection(host)
            try:
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                status = int(resp.status)
                resp_headers = {str(k).lower(): str(v) for k, v in resp.getheaders()}
                body, too_large = self._read_body(resp)
            except _STALE_ERRORS:
                self._drop(host)
                if reused and attempt == 0:
                    continue
                raise
            except BaseException:
                self._drop(host)
                raise
            if too_large:
                self._drop(host)  # unread remainder makes the connection unusable
                raise SourceError("response_too_large")
            return status, resp_headers, body
        raise SourceError("connection_error")  # unreachable

    def _decode(self, body: bytes, headers: dict[str, str]) -> bytes:
        if headers.get("content-encoding", "").strip().lower() != "gzip":
            return body
        try:
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = inflater.decompress(body, self.max_bytes + 1)
        except zlib.error:
            raise SourceError("bad_gzip") from None
        if len(out) > self.max_bytes or inflater.unconsumed_tail:
            raise SourceError("response_too_large")
        return out

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        }
        request_headers.update(headers or {})
        current = url
        redirects = 0
        retries = 0
        while True:
            host, path = self._check_url(current)
            request_headers["Host"] = host
            self.gate.acquire()
            try:
                status, resp_headers, body = self._once(host, path, request_headers)
            except SourceError:
                raise
            except ssl.SSLCertVerificationError:
                raise SourceError("tls_verification_failed") from None
            except (TimeoutError, OSError, http.client.HTTPException) as exc:
                reason = "timeout" if isinstance(exc, TimeoutError) else "connection_error"
                retries = self._backoff(retries, reason)
                continue

            if status == 429:
                if retries >= self.max_retries:
                    raise SourceError("rate_limited")
                retries += 1
                self.gate.cooldown(parse_retry_after(resp_headers.get("retry-after"), self._wall_clock()))
                continue
            if status >= 500:
                retries = self._backoff(retries, f"http_{status}")
                continue
            if status in REDIRECT_STATUSES:
                location = resp_headers.get("location")
                if not location:
                    raise SourceError("redirect_without_location")
                redirects += 1
                if redirects > MAX_REDIRECTS:
                    raise SourceError("too_many_redirects")
                target = urljoin(current, location)
                try:
                    self._check_url(target)
                except SourceError as exc:
                    raise SourceError(f"redirect_{exc.reason}") from None
                current = target
                continue
            return HttpResponse(status=status, body=self._decode(body, resp_headers), url=current, headers=resp_headers)

    def _backoff(self, retries: int, reason: str) -> int:
        if retries >= self.max_retries:
            raise SourceError(reason)
        self._sleep(float(2 ** retries))
        return retries + 1
