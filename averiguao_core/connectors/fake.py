"""Offline connectors and the synthetic "Example Corp" world.

``FakeConnector`` implements ``contracts.Connector`` from a canned response table, so the whole pipeline runs with no
network. ``demo_world()`` returns one per source describing a small, realistic organization; it drives both the
acceptance tests and ``python3 averiguao.py --demo``.

All data is fictional. Addresses come only from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), the organization's names live under example.com, and every outside party uses the reserved ``.test``
TLD (saasvendor.test, cdn.test, other-customer.test, ...).

The Example Corp world (seeds ``example.com`` and ``198.51.100.0/28``, organization "Example Corp"):

* KNOWN        www.example.com -> 198.51.100.2; the hostname and the 198.51.100.0/30 "web tier" are inventoried.
               mail.example.com also resolves to 198.51.100.3 (inventoried by the /30).
* NEW          staging.example.com (CT) -> 198.51.100.9, inside Example Corp's RDAP block, not inventoried,
               InternetDB shows SSH and HTTPS open and a known vulnerability.
               198.51.100.5 answers InternetDB inside the approved /28 and reports vpn.example.com.
               legacy.example.com appears only in a certificate that expired in 2019 and no longer resolves.
* UNEXPLAINED  app.example.com -> 203.0.113.50, registered to "Generic Cloud Hosting LLC": an organizational name
               points at an address nobody can show the organization owns or controls.
* CONFLICT     mail.example.com resolves to an Example Corp address and to the Generic Cloud address.
* THIRD-PARTY  status.example.com is a CNAME to a status-page vendor (saasvendor.test), and cdn.example.com is a CNAME
               chain into a CDN (cdn.test). Both hostnames and their addresses are vendor dependencies.
* TRAPS        A shared certificate also names shop.other-customer.test and example.com.evil.test (out of scope).
               InternetDB on 203.0.113.50 lists another tenant, tenant-a.unrelated.test (context only).
               A wildcard certificate *.example.com adds nothing new. 198.51.100.16/.17 sit next to the approved /28
               and must never be queried. 198.51.100.11 makes InternetDB fail, to show source failures.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from ..contracts import SourceResult

FIXED_CLOCK = "2026-10-01T00:00:00+00:00"

Response = Any  # dict (ok) | "no_record" | "error" | callable(query) -> one of those

_URLS = {
    "ct": "https://crt.sh/?q=%25.{q}&output=json",
    "dns": "https://cloudflare-dns.com/dns-query?name={q}&type=A",
    "rdap": "https://rdap.org/ip/{q}",
    "internetdb": "https://internetdb.shodan.io/{q}",
}


def canonical_sha256(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FakeConnector:
    """Deterministic connector. ``responses`` maps query -> data dict (status ok), "no_record", "error", or a callable
    taking the query and returning one of those (an exception from the callable becomes status "error").
    Queries missing from ``responses`` go to ``fallback`` (a callable, if given), else return "no_record".
    ``on_call(connector, query)`` runs on every call before answering (tests use it to pause a run).
    Every query is appended to ``calls`` (thread-safe)."""

    def __init__(self, name: str, responses: Mapping[str, Response] | None = None, *,
                 clock: str | Callable[[], str] = FIXED_CLOCK,
                 fallback: Callable[[str], Response] | None = None,
                 on_call: Callable[["FakeConnector", str], None] | None = None):
        if name not in _URLS:
            raise ValueError(f"unknown source {name!r}")
        self.name = name
        self.responses: dict[str, Response] = dict(responses or {})
        self.clock = clock
        self.fallback = fallback
        self.on_call = on_call
        self._lock = threading.Lock()
        self.calls: list[str] = []

    def _now(self) -> str:
        return self.clock() if callable(self.clock) else self.clock

    def queries(self) -> list[str]:
        with self._lock:
            return list(self.calls)

    def fetch(self, query: str) -> SourceResult:
        with self._lock:
            self.calls.append(query)
        if self.on_call is not None:
            self.on_call(self, query)
        if query in self.responses:
            response = self.responses[query]
        elif self.fallback is not None:
            response = self.fallback(query)
        else:
            response = "no_record"
        if callable(response):
            try:
                response = response(query)
            except Exception as exc:  # a failing callable simulates a source failure
                response = "error:" + type(exc).__name__
        url = _URLS[self.name].format(q=query)
        retrieved_at = self._now()
        if isinstance(response, dict):
            data = json.loads(json.dumps(response))  # defensive deep copy
            return SourceResult(source=self.name, query=query, status="ok", retrieved_at=retrieved_at,  # type: ignore[arg-type]
                                source_url=url, raw_sha256=canonical_sha256(data), data=data)
        if response == "no_record":
            return SourceResult(source=self.name, query=query, status="no_record",  # type: ignore[arg-type]
                                retrieved_at=retrieved_at, source_url=url, raw_sha256=None, data={})
        if isinstance(response, str) and response.startswith("error"):
            reason = response.partition(":")[2] or "simulated source failure"
            return SourceResult(source=self.name, query=query, status="error",  # type: ignore[arg-type]
                                retrieved_at=retrieved_at, source_url=url, raw_sha256=None, data={}, error=reason)
        raise ValueError(f"bad fake response for {self.name} {query!r}: {response!r}")


def all_calls(world: Mapping[str, FakeConnector]) -> list[tuple[str, str]]:
    """Every (source, query) asked of a world, grouped by source."""
    return [(name, q) for name, conn in world.items() for q in conn.queries()]


# --------------------------------------------------------------------------- the Example Corp world

DEMO_CONFIG: dict[str, Any] = {
    "seeds": "example.com\n198.51.100.0/28",
    "approval_ref": "DEMO-0001 (synthetic Example Corp engagement)",
    "scope_version": "1",
    "org_names": ["Example Corp"],
    "label": "Example Corp demo (synthetic data, no network)",
}

DEMO_INVENTORY_CSV = (
    "value,label\n"
    "198.51.100.0/30,web tier\n"
    "www.example.com,public website\n"
    "10.0.0.0/8,corporate LAN\n"
)

LEGACY_CERT_NOT_BEFORE = "2018-06-01T00:00:00+00:00"
LEGACY_CERT_NOT_AFTER = "2019-06-01T00:00:00+00:00"

# Candidate asset id -> (expected queue, why). Every hostname/ip candidate of the demo run, nothing else.
DEMO_EXPECTED: dict[str, tuple[str, str]] = {
    "hostname:www.example.com": ("known", "exact match to inventory hostname www.example.com"),
    "ip:198.51.100.2": ("known", "inside inventoried 198.51.100.0/30 (prefix containment)"),
    "ip:198.51.100.3": ("known", "inside inventoried 198.51.100.0/30 (prefix containment)"),
    "hostname:staging.example.com": ("new", "in-scope name from CT, not inventoried"),
    "ip:198.51.100.9": ("new", "RDAP says Example Corp; not inventoried; open ports and a vulnerability"),
    "ip:198.51.100.5": ("new", "member of the approved /28 with InternetDB data; RDAP says Example Corp"),
    "hostname:vpn.example.com": ("new", "in-scope name reported by InternetDB on 198.51.100.5"),
    "hostname:legacy.example.com": ("new", "only in a certificate that expired in 2019; does not resolve"),
    "hostname:app.example.com": ("new", "in-scope name; no external CNAME; not inventoried"),
    "hostname:mail.example.com": ("new", "in-scope name; resolves to two different providers (conflict)"),
    "ip:203.0.113.50": ("unexplained", "registered to Generic Cloud Hosting LLC; control unknown"),
    "hostname:status.example.com": ("third_party", "CNAME to a status-page vendor (saasvendor.test)"),
    "ip:203.0.113.80": ("third_party", "reached only through the vendor CNAME; registered to SaaS Vendor Inc"),
    "hostname:cdn.example.com": ("third_party", "CNAME chain into a CDN (cdn.test)"),
    "ip:203.0.113.99": ("third_party", "reached only through the CDN CNAME; registered to CDN Provider Ltd"),
}

# Names and addresses that no source may ever be asked about.
DEMO_NEVER_QUERIED = ("shop.other-customer.test", "example.com.evil.test", "tenant-a.unrelated.test",
                      "edge.cdn.test", "example-corp.statuspage.saasvendor.test", "198.51.100.16", "198.51.100.17",
                      "vpn.example.com")

_RDAP_EXAMPLE_CORP = {"handle": "NET-198-51-100-0-1", "network_name": "EXAMPLE-CORP-NET", "cidrs": ["198.51.100.0/24"],
                      "org_names": ["Example Corp"], "entity_handles": ["EXCO-1"], "country": "US",
                      "registration_date": "2011-03-14T00:00:00+00:00", "last_changed": "2024-02-01T00:00:00+00:00"}

_RDAP_203 = [
    (0, 63, {"handle": "NET-203-0-113-0-1", "network_name": "GENERIC-CLOUD-1", "cidrs": ["203.0.113.0/26"],
             "org_names": ["Generic Cloud Hosting LLC"], "entity_handles": ["GCH-7"], "country": "US",
             "registration_date": "2015-07-01T00:00:00+00:00", "last_changed": "2025-11-20T00:00:00+00:00"}),
    (64, 95, {"handle": "NET-203-0-113-64-1", "network_name": "SAASVENDOR-NET", "cidrs": ["203.0.113.64/27"],
              "org_names": ["SaaS Vendor Inc"], "entity_handles": ["SVI-2"], "country": "IE",
              "registration_date": "2018-01-09T00:00:00+00:00", "last_changed": "2025-05-05T00:00:00+00:00"}),
    (96, 127, {"handle": "NET-203-0-113-96-1", "network_name": "CDNPROV-EDGE", "cidrs": ["203.0.113.96/27"],
               "org_names": ["CDN Provider Ltd"], "entity_handles": ["CDNP-1"], "country": "GB",
               "registration_date": "2016-04-22T00:00:00+00:00", "last_changed": "2026-01-15T00:00:00+00:00"}),
]


def _rdap_lookup(query: str) -> Response:
    parts = query.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return "no_record"
    if query.startswith("198.51.100."):
        return _RDAP_EXAMPLE_CORP
    if query.startswith("203.0.113."):
        last = int(parts[3])
        for lo, hi, data in _RDAP_203:
            if lo <= last <= hi:
                return data
    return "no_record"


def _day(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT00:00:00+00:00")


def demo_world(*, clock: str | Callable[[], str] = FIXED_CLOCK,
               overrides: Mapping[str, Mapping[str, Response]] | None = None) -> dict[str, FakeConnector]:
    """Fresh connectors for the Example Corp world. Current certificates are valid from 90 days ago to 275 days from
    now (so they never go stale); the legacy certificate expired in 2019. ``overrides`` replaces individual responses:
    {"rdap": {"203.0.113.50": {...}}}."""
    today = datetime.now(timezone.utc)
    nb, na = _day(today - timedelta(days=90)), _day(today + timedelta(days=275))
    ca = "C=US, O=Example Trust CA, CN=Example Trust RSA CA 2026"

    def cert(cid: str, names: list[str], issuer: str = ca, not_before: str = nb, not_after: str = na) -> dict:
        return {"id": cid, "names": sorted(set(names)), "not_before": not_before, "not_after": not_after,
                "issuer": issuer}

    ct = {
        "example.com": {"certificates": [
            cert("9100000001", ["example.com", "www.example.com"]),
            cert("9100000002", ["*.example.com", "example.com"]),                 # wildcard: nothing new
            cert("9100000003", ["staging.example.com"]),
            cert("9100000004", ["app.example.com", "mail.example.com"]),
            cert("9100000005", ["status.example.com"], issuer="C=US, O=Vendor Managed CA"),
            cert("9100000006", ["cdn.example.com"], issuer="C=GB, O=CDN Provider Ltd CA"),
            cert("9100000007", ["example.com", "example.com.evil.test", "shop.other-customer.test"],
                 issuer="C=US, O=Shared Hosting CA"),                             # shared certificate: two out of scope
            cert("9100000008", ["legacy.example.com"], not_before=LEGACY_CERT_NOT_BEFORE,
                 not_after=LEGACY_CERT_NOT_AFTER),                                # expired 2019
        ]},
    }

    def a(name: str, addresses: list[str], cnames: list[str] | None = None) -> dict:
        return {"name": name, "cnames": list(cnames or []), "addresses": sorted(addresses), "ttl": 300}

    dns = {
        "example.com": a("example.com", ["198.51.100.2"]),
        "www.example.com": a("www.example.com", ["198.51.100.2"]),
        "staging.example.com": a("staging.example.com", ["198.51.100.9"]),
        "app.example.com": a("app.example.com", ["203.0.113.50"]),
        "mail.example.com": a("mail.example.com", ["198.51.100.3", "203.0.113.50"]),
        "status.example.com": a("status.example.com", ["203.0.113.80"],
                                ["example-corp.statuspage.saasvendor.test"]),
        "cdn.example.com": a("cdn.example.com", ["203.0.113.99"], ["example-corp.cdn.test", "edge.cdn.test"]),
        "legacy.example.com": "no_record",
    }

    def idb(ports=(), hostnames=(), cpes=(), tags=(), vulns=()) -> dict:
        return {"ports": sorted(set(ports)), "hostnames": sorted(set(hostnames)), "cpes": sorted(set(cpes)),
                "tags": sorted(set(tags)), "vulns": sorted(set(vulns))}

    internetdb: dict[str, Response] = {f"198.51.100.{i}": "no_record" for i in range(16)}
    internetdb.update({
        "198.51.100.2": idb(ports=[80, 443], cpes=["cpe:/a:nginx:nginx"]),
        "198.51.100.5": idb(ports=[443], hostnames=["vpn.example.com"], tags=["vpn"]),
        "198.51.100.9": idb(ports=[22, 443], cpes=["cpe:/a:openbsd:openssh:8.9p1"], vulns=["CVE-2023-48795"]),
        "198.51.100.11": "error",
        "203.0.113.50": idb(ports=[22, 80, 443], hostnames=["tenant-a.unrelated.test"], tags=["cloud"]),
        "203.0.113.80": "no_record",
        "203.0.113.99": idb(ports=[80, 443], hostnames=["edge.cdn.test", "www.another-brand.test"], tags=["cdn"]),
    })

    tables: dict[str, dict[str, Response]] = {"ct": ct, "dns": dns, "rdap": {}, "internetdb": internetdb}
    for source, items in (overrides or {}).items():
        tables[source].update(items)
    return {
        "ct": FakeConnector("ct", tables["ct"], clock=clock),
        "dns": FakeConnector("dns", tables["dns"], clock=clock),
        "rdap": FakeConnector("rdap", tables["rdap"], clock=clock, fallback=_rdap_lookup),
        "internetdb": FakeConnector("internetdb", tables["internetdb"], clock=clock),
    }
