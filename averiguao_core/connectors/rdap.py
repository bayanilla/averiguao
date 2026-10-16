"""IP network registration via RDAP: rdap.org bootstrap, redirected to the responsible RIR.

org_names come from the vCard ``fn`` and ``org`` of entities with role "registrant" (searched
recursively). When there is no registrant, every entity except abuse-only contacts is used, so an
abuse mailbox name ("Abuse-C Role") is never presented as an organization name.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from ..contracts import SourceResult
from .common import normalize_ipv4, result, to_utc_iso
from .http import HttpClient, SourceError

BOOTSTRAP_HOST = "rdap.org"
RIR_HOSTS = frozenset({
    "rdap.arin.net",       # https://rdap.arin.net/registry/ip/<ip>
    "rdap.db.ripe.net",    # https://rdap.db.ripe.net/ip/<ip>
    "rdap.apnic.net",      # https://rdap.apnic.net/ip/<ip>
    "rdap.lacnic.net",     # https://rdap.lacnic.net/rdap/ip/<ip>
    "rdap.afrinic.net",    # https://rdap.afrinic.net/rdap/ip/<ip>
})
ALLOWED_HOSTS = frozenset({BOOTSTRAP_HOST}) | RIR_HOSTS
MAX_ENTITY_DEPTH = 6


def _str(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _walk_entities(entities: Any, depth: int = 0):
    if depth > MAX_ENTITY_DEPTH or not isinstance(entities, list):
        return
    for entity in entities:
        if isinstance(entity, dict):
            yield entity
            yield from _walk_entities(entity.get("entities"), depth + 1)


def _roles(entity: dict[str, Any]) -> set[str]:
    roles = entity.get("roles")
    return {r.lower() for r in roles if isinstance(r, str)} if isinstance(roles, list) else set()


def _vcard_names(entity: dict[str, Any]) -> list[str]:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list)):
        return []
    names = []
    for prop in vcard[1]:
        if not (isinstance(prop, list) and len(prop) >= 4 and prop[0] in ("fn", "org")):
            continue
        values = prop[3:]
        for value in values:
            # "org" may carry structured components as a list.
            parts = value if isinstance(value, list) else [value]
            for part in parts:
                text = _str(part)
                if text:
                    names.append(text)
    return names


def _cidrs(payload: dict[str, Any]) -> list[str]:
    nets: set[ipaddress.IPv4Network] = set()
    for item in payload.get("cidr0_cidrs") or []:
        if isinstance(item, dict) and isinstance(item.get("v4prefix"), str) and isinstance(item.get("length"), int):
            try:
                nets.add(ipaddress.IPv4Network(f"{item['v4prefix']}/{item['length']}", strict=False))
            except ValueError:
                pass
    if not nets:
        try:
            start = ipaddress.IPv4Address(str(payload.get("startAddress", "")).strip())
            end = ipaddress.IPv4Address(str(payload.get("endAddress", "")).strip())
            if start <= end:
                nets.update(ipaddress.summarize_address_range(start, end))
        except ValueError:
            pass
    return [str(n) for n in sorted(nets)]


def map_rdap(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("unexpected_json")
    entities = list(_walk_entities(payload.get("entities")))
    registrants = [e for e in entities if "registrant" in _roles(e)]
    named = registrants or [e for e in entities if _roles(e) != {"abuse"}]
    org_names = sorted({n for e in named for n in _vcard_names(e)})
    handles = sorted({h for h in (_str(e.get("handle")) for e in entities) if h})
    events = {}
    for event in payload.get("events") or []:
        if isinstance(event, dict) and isinstance(event.get("eventAction"), str):
            action = event["eventAction"].strip().lower()
            if action not in events:
                events[action] = to_utc_iso(event.get("eventDate"))
    country = _str(payload.get("country"))
    return {
        "handle": _str(payload.get("handle")),
        "network_name": _str(payload.get("name")),
        "cidrs": _cidrs(payload),
        "org_names": org_names,
        "entity_handles": handles,
        "country": country.upper() if country else None,
        "registration_date": events.get("registration"),
        "last_changed": events.get("last changed"),
    }


class RDAPConnector:
    name = "rdap"
    DEFAULT_RATE = 1
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, rate: float = DEFAULT_RATE, *, client: HttpClient | None = None, **client_kwargs: Any):
        self.client = client or HttpClient(rate=rate, allowed_hosts=ALLOWED_HOSTS, max_bytes=self.MAX_BYTES,
                                           timeout=30, **client_kwargs)

    def fetch(self, query: str) -> SourceResult:
        ip = normalize_ipv4(query)
        if ip is None:
            return result("rdap", str(query), "error", "", error="invalid_query")
        url = f"https://{BOOTSTRAP_HOST}/ip/{ip}"
        try:
            resp = self.client.get(url, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status == 404:
                return result("rdap", ip, "no_record", url, raw=resp.body)
            if resp.status != 200:
                return result("rdap", ip, "error", url, raw=resp.body, error=f"http_{resp.status}")
            try:
                payload = json.loads(resp.body.decode("utf-8"))
                data = map_rdap(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return result("rdap", ip, "error", url, raw=resp.body, error="not_json")
            except ValueError as exc:
                return result("rdap", ip, "error", url, raw=resp.body, error=str(exc))
            return result("rdap", ip, "ok", url, raw=resp.body, data=data)
        except SourceError as exc:
            return result("rdap", ip, "error", url, error=exc.reason)
        except Exception:
            return result("rdap", ip, "error", url, error="internal_error")
