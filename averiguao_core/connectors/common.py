"""Helpers shared by the connectors: query validation, time formatting, result construction."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from ..contracts import SourceName, SourceResult

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def normalize_hostname(value: str) -> str | None:
    """Lowercase, strip one trailing dot; None unless it is a multi-label DNS hostname (not an IP)."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return name


def normalize_ipv4(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        return None


def clean_name(value: Any) -> str | None:
    """A logged name (may be a wildcard) lowercased without trailing dot; None if empty or not name-like."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    if not name or not re.fullmatch(r"[a-z0-9*_.-]+", name):
        return None
    return name


def to_utc_iso(value: Any) -> str | None:
    """Parse an ISO-8601 timestamp (naive => UTC) into ``YYYY-MM-DDTHH:MM:SS+00:00``; None if unparseable."""
    if not isinstance(value, str):
        return None
    m = _ISO.match(value.strip())
    if not m:
        return None
    tz = m.group(4)
    if tz is None or tz == "Z":
        tz = "+00:00"
    elif ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    try:
        parsed = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{tz}")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def result(source: SourceName, query: str, status: str, source_url: str, *,
           raw: bytes | None = None, raw_sha256: str | None = None,
           data: dict[str, Any] | None = None, error: str | None = None) -> SourceResult:
    if raw is not None and raw_sha256 is None:
        raw_sha256 = sha256_hex(raw)
    return SourceResult(
        source=source,
        query=query,
        status=status,  # type: ignore[arg-type]
        retrieved_at=now_iso(),
        source_url=source_url,
        raw_sha256=raw_sha256,
        data=(data or {}) if status == "ok" else {},
        error=error if status == "error" else None,
    )
