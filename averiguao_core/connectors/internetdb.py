"""Shodan InternetDB: open ports, hostnames, CPEs, tags and vulns last seen for an IPv4 address."""

from __future__ import annotations

import json
from typing import Any

from ..contracts import SourceResult
from .common import clean_name, normalize_ipv4, result
from .http import HttpClient, SourceError

HOST = "internetdb.shodan.io"
LIST_CAP = 1000


def map_internetdb(ip: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("ip") != ip:
        raise ValueError("unexpected_response")

    def strings(key: str) -> list[str]:
        values = payload.get(key)
        if not isinstance(values, list):
            return []
        return sorted({v.strip() for v in values if isinstance(v, str) and v.strip()})[:LIST_CAP]

    ports_raw = payload.get("ports") if isinstance(payload.get("ports"), list) else []
    ports = sorted({p for p in ports_raw if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535})
    hostnames_raw = payload.get("hostnames") if isinstance(payload.get("hostnames"), list) else []
    hostnames = sorted({n for n in (clean_name(h) for h in hostnames_raw) if n})
    return {
        "ports": ports[:LIST_CAP],
        "hostnames": hostnames[:LIST_CAP],
        "cpes": strings("cpes"),
        "tags": strings("tags"),
        "vulns": strings("vulns"),
    }


class InternetDBConnector:
    name = "internetdb"
    DEFAULT_RATE = 5
    MAX_BYTES = 64 * 1024

    def __init__(self, rate: float = DEFAULT_RATE, *, client: HttpClient | None = None, **client_kwargs: Any):
        self.client = client or HttpClient(rate=rate, allowed_hosts={HOST}, max_bytes=self.MAX_BYTES,
                                           timeout=12, **client_kwargs)

    def fetch(self, query: str) -> SourceResult:
        ip = normalize_ipv4(query)
        if ip is None:
            return result("internetdb", str(query), "error", "", error="invalid_query")
        url = f"https://{HOST}/{ip}"
        try:
            resp = self.client.get(url, headers={"Accept": "application/json"})
            if resp.status == 404:
                return result("internetdb", ip, "no_record", url, raw=resp.body)
            if resp.status != 200:
                return result("internetdb", ip, "error", url, raw=resp.body, error=f"http_{resp.status}")
            try:
                data = map_internetdb(ip, json.loads(resp.body.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return result("internetdb", ip, "error", url, raw=resp.body, error="not_json")
            except ValueError as exc:
                return result("internetdb", ip, "error", url, raw=resp.body, error=str(exc))
            return result("internetdb", ip, "ok", url, raw=resp.body, data=data)
        except SourceError as exc:
            return result("internetdb", ip, "error", url, error=exc.reason)
        except Exception:
            return result("internetdb", ip, "error", url, error="internal_error")
