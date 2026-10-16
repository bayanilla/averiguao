"""Certificate Transparency via crt.sh.

Two requests per domain, merged by certificate id: ``q=%.<domain>`` (names under the domain) and
``q=<domain>`` (the apex itself, which the ``%.`` pattern does not match). ``raw_sha256`` is the
sha256 of the two raw bodies joined by a single newline, in that order. Either request failing
makes the whole result an error; nothing partial is returned.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from ..contracts import SourceResult
from .common import clean_name, normalize_hostname, result, to_utc_iso
from .http import HttpClient, SourceError

HOST = "crt.sh"


def _url(q: str) -> str:
    return f"https://{HOST}/?q={quote(q, safe='')}&output=json"


def parse_entries(body: bytes) -> list[dict[str, Any]]:
    """Raise ValueError unless the body is a crt.sh JSON array of objects."""
    try:
        entries = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("not_json") from None
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError("unexpected_json")
    return entries


def merge_certificates(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    certs: dict[str, dict[str, Any]] = {}
    for entry in entries:
        raw_id = entry.get("id")
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)) or str(raw_id).strip() == "":
            continue
        cid = str(raw_id).strip()
        names: set[str] = set()
        name_value = entry.get("name_value")
        if isinstance(name_value, str):
            names.update(n for n in (clean_name(part) for part in name_value.split("\n")) if n)
        common = clean_name(entry.get("common_name"))
        if common:
            names.add(common)
        issuer = entry.get("issuer_name")
        cert = certs.setdefault(cid, {"id": cid, "names": set(), "not_before": None, "not_after": None, "issuer": None})
        cert["names"] |= names
        cert["not_before"] = cert["not_before"] or to_utc_iso(entry.get("not_before"))
        cert["not_after"] = cert["not_after"] or to_utc_iso(entry.get("not_after"))
        if cert["issuer"] is None and isinstance(issuer, str) and issuer.strip():
            cert["issuer"] = issuer.strip()
    out = []
    for cid in sorted(certs, key=lambda c: (0, int(c), c) if c.isdigit() else (1, 0, c)):
        cert = certs[cid]
        cert["names"] = sorted(cert["names"])
        out.append(cert)
    return out


class CTConnector:
    name = "ct"
    DEFAULT_RATE = 0.5
    MAX_BYTES = 50 * 1024 * 1024

    def __init__(self, rate: float = DEFAULT_RATE, *, client: HttpClient | None = None, **client_kwargs: Any):
        self.client = client or HttpClient(rate=rate, allowed_hosts={HOST}, max_bytes=self.MAX_BYTES,
                                           timeout=60, **client_kwargs)

    def fetch(self, query: str) -> SourceResult:
        domain = normalize_hostname(query)
        if domain is None or domain.startswith("*") or "_" in domain:
            return result("ct", str(query), "error", "", error="invalid_query")
        url = _url(f"%.{domain}")
        bodies: list[bytes] = []
        entries: list[dict[str, Any]] = []
        try:
            for q in (f"%.{domain}", domain):
                resp = self.client.get(_url(q), headers={"Accept": "application/json"})
                if resp.status != 200:
                    return result("ct", domain, "error", url, raw=resp.body, error=f"http_{resp.status}")
                bodies.append(resp.body)
                entries.extend(parse_entries(resp.body))
        except SourceError as exc:
            return result("ct", domain, "error", url, error=exc.reason)
        except ValueError as exc:
            return result("ct", domain, "error", url, raw=b"\n".join(bodies), error=str(exc))
        except Exception:
            return result("ct", domain, "error", url, error="internal_error")
        raw = b"\n".join(bodies)
        certs = merge_certificates(entries)
        if not certs:
            return result("ct", domain, "no_record", url, raw=raw)
        return result("ct", domain, "ok", url, raw=raw, data={"certificates": certs})
