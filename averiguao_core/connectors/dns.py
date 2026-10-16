"""Live A-record resolution through Cloudflare DNS-over-HTTPS (JSON API).

Never contacts the investigated hosts. NXDOMAIN, or NOERROR without A records, is "no_record"
(data is empty then, per the contract, so a dangling CNAME chain is not reported).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from ..contracts import SourceResult
from .common import normalize_hostname, normalize_ipv4, result
from .http import HttpClient, SourceError

HOST = "cloudflare-dns.com"
MAX_CNAME_CHAIN = 16


def _name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    return name[:-1] if name.endswith(".") else name


def parse_doh(query: str, payload: Any) -> tuple[str, dict[str, Any] | None, str | None]:
    """Return (status, data, error) for a DoH JSON payload answering ``query`` type A."""
    if not isinstance(payload, dict) or not isinstance(payload.get("Status"), int):
        return "error", None, "unexpected_json"
    rcode = payload["Status"]
    if rcode == 3:
        return "no_record", None, None
    if rcode != 0:
        return "error", None, f"dns_rcode_{rcode}"
    answers = [a for a in payload.get("Answer") or [] if isinstance(a, dict)]
    cname_of: dict[str, str] = {}
    for a in answers:
        if a.get("type") == 5:
            owner, target = _name(a.get("name")), _name(a.get("data"))
            if owner and target and owner not in cname_of:
                cname_of[owner] = target
    chain: list[str] = []
    current = query
    while current in cname_of and len(chain) < MAX_CNAME_CHAIN and cname_of[current] not in chain:
        current = cname_of[current]
        chain.append(current)
    a_records = [a for a in answers if a.get("type") == 1 and _name(a.get("name")) == current]
    if not a_records and not chain:
        # Some resolvers echo the name with different case or omit it; accept any A when there is no chain.
        a_records = [a for a in answers if a.get("type") == 1]
    addresses = sorted({ip for ip in (normalize_ipv4(a.get("data")) for a in a_records) if ip},
                       key=lambda s: tuple(int(p) for p in s.split(".")))
    if not addresses:
        return "no_record", None, None
    ttls = [a["TTL"] for a in a_records if isinstance(a.get("TTL"), int) and not isinstance(a.get("TTL"), bool)]
    return "ok", {"name": query, "cnames": chain, "addresses": addresses, "ttl": min(ttls) if ttls else None}, None


class DNSConnector:
    name = "dns"
    DEFAULT_RATE = 10
    MAX_BYTES = 256 * 1024

    def __init__(self, rate: float = DEFAULT_RATE, *, client: HttpClient | None = None, **client_kwargs: Any):
        self.client = client or HttpClient(rate=rate, allowed_hosts={HOST}, max_bytes=self.MAX_BYTES, **client_kwargs)

    def fetch(self, query: str) -> SourceResult:
        name = normalize_hostname(query)
        if name is None:
            return result("dns", str(query), "error", "", error="invalid_query")
        url = f"https://{HOST}/dns-query?" + urlencode({"name": name, "type": "A"})
        try:
            resp = self.client.get(url, headers={"Accept": "application/dns-json"})
            if resp.status != 200:
                return result("dns", name, "error", url, raw=resp.body, error=f"http_{resp.status}")
            try:
                payload = json.loads(resp.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return result("dns", name, "error", url, raw=resp.body, error="not_json")
            status, data, error = parse_doh(name, payload)
            return result("dns", name, status, url, raw=resp.body, data=data, error=error)
        except SourceError as exc:
            return result("dns", name, "error", url, error=exc.reason)
        except Exception:
            return result("dns", name, "error", url, error="internal_error")
