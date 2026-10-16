"""Shared records and interfaces. Frozen for Stage 1: modules depend on these, never on each other's internals.

Every record serializes with ``to_dict()`` into plain JSON types. Timestamps are UTC ISO-8601 strings
(``2026-10-16T11:05:40+00:00``). Unknown values are ``None``, never a substituted guess.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol


VERSION = "0.2.0"
USER_AGENT = f"Averiguao/{VERSION} (+https://github.com/bayanilla/averiguao)"


class Record:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[call-overload]


# --------------------------------------------------------------------------- scope and configuration

SeedType = Literal["domain", "ip", "prefix"]


@dataclass(frozen=True)
class Seed(Record):
    id: str                 # "seed:1", "seed:2", ... in input order
    type: SeedType
    value: str              # normalized: lowercase domain without trailing dot, canonical IPv4, canonical CIDR
    approval_ref: str       # who or what approved this scope (ticket, letter, contract); required, non-empty
    scope_version: str      # caller-supplied label for the scope document version; "1" by default


@dataclass(frozen=True)
class Limits(Record):
    max_depth: int = 2                  # relationship hops from a seed (enrichment never adds a hop)
    max_hostnames: int = 500            # distinct hostname candidates per run
    max_addresses: int = 4096           # distinct IP candidates per run, including prefix seed members
    max_queries: int = 10_000           # connector calls per run (cache hits do not count)
    max_seconds: int = 3600             # wall-clock time spent running (summed across resumes)
    max_prefix_addresses: int = 4096    # largest prefix seed accepted; hard ceiling HARD_MAX_PREFIX_ADDRESSES


HARD_MAX_PREFIX_ADDRESSES = 65_536


@dataclass(frozen=True)
class MatchRules(Record):
    exact: bool = True                  # always on; listed for report reproducibility
    prefix_containment: bool = True     # IP inside an inventoried CIDR counts as matched
    domain_hierarchy: bool = False      # hostname under an inventoried "*.domain" entry counts as matched


@dataclass(frozen=True)
class RunConfig(Record):
    seeds: tuple[Seed, ...]
    org_names: tuple[str, ...]          # organization identifiers matched against RDAP names/handles (case-insensitive)
    limits: Limits = field(default_factory=Limits)
    match_rules: MatchRules = field(default_factory=MatchRules)
    label: str = ""                     # free text shown in the UI


# --------------------------------------------------------------------------- inventory

InventoryKind = Literal["ip", "cidr", "hostname", "domain_tree"]


@dataclass(frozen=True)
class InventoryEntry(Record):
    id: str                  # "inv:<n>" stable within its snapshot, in file order
    kind: InventoryKind      # domain_tree comes from "*.example.com" and covers the domain and every name under it
    value: str               # normalized; domain_tree stores the base domain ("example.com")
    label: str


@dataclass(frozen=True)
class InventorySnapshot(Record):
    id: str                  # "snap:<sha256 of normalized entries, first 16 hex>"
    as_of: str               # analyst-supplied as-of time, else import time
    imported_at: str
    label: str
    entries: tuple[InventoryEntry, ...]


# --------------------------------------------------------------------------- source results (connector output)

SourceName = Literal["ct", "dns", "rdap", "internetdb"]
SourceStatus = Literal["ok", "no_record", "error"]


@dataclass
class SourceResult(Record):
    """One connector call. ``data`` follows the per-source schema below; it is ``{}`` unless status == "ok"."""
    source: SourceName
    query: str
    status: SourceStatus
    retrieved_at: str
    source_url: str
    raw_sha256: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None            # short, non-sensitive reason when status == "error"


# Per-source ``data`` schemas (all lists deduplicated and sorted, names lowercase without trailing dot):
#
# ct (query = approved domain):
#   {"certificates": [{"id": str, "names": [str], "not_before": iso|None, "not_after": iso|None, "issuer": str|None}]}
#   Names are as logged, including wildcard forms like "*.example.com". The connector does not filter by scope.
# dns (query = hostname):
#   {"name": str, "cnames": [str, ...] (chain order), "addresses": [ipv4 str], "ttl": int|None}
#   NXDOMAIN or no A record => status "no_record".
# rdap (query = ipv4):
#   {"handle": str|None, "network_name": str|None, "cidrs": [str], "org_names": [str], "entity_handles": [str],
#    "country": str|None, "registration_date": iso|None, "last_changed": iso|None}
# internetdb (query = ipv4):
#   {"ports": [int], "hostnames": [str], "cpes": [str], "tags": [str], "vulns": [str]}
#   HTTP 404 => status "no_record".


class Connector(Protocol):
    name: SourceName

    def fetch(self, query: str) -> SourceResult:
        """Return a SourceResult. Never raises for source failures: those become status "error"."""
        ...


# --------------------------------------------------------------------------- discovery records

AssetType = Literal["domain", "hostname", "ip"]


@dataclass(frozen=True)
class Asset(Record):
    id: str                  # f"{type}:{value}", e.g. "ip:198.51.100.42", "hostname:portal.example.com"
    type: AssetType
    value: str


def asset_id(type_: AssetType, value: str) -> str:
    return f"{type_}:{value}"


@dataclass(frozen=True)
class Evidence(Record):
    id: str                          # "ev:<sha256(source|query|retrieved_at|raw_sha256), first 16 hex>"; seeds use "ev:seed:<n>"
    source: str                      # a SourceName, or "scope" for seed approval evidence
    query: str
    source_url: str
    raw_sha256: str | None
    observed_at: str                 # when Averiguao retrieved it
    valid_from: str | None           # validity reported by the source (certificate not_before); None if not reported
    valid_to: str | None
    source_record_id: str | None     # e.g. crt.sh certificate id, RDAP handle
    data: dict[str, Any]


Predicate = Literal[
    "seed_is",                          # seed -> its own asset (domain or ip); depth 0
    "prefix_contains_ip",               # prefix seed -> member ip with an observation; depth 1
    "certificate_mentions_hostname",    # domain -> hostname, from CT
    "hostname_resolves_to_ip",          # domain/hostname -> ip, from DNS
    "ip_reports_hostname",              # ip -> hostname, from InternetDB hostnames (in approved domain only)
]


@dataclass(frozen=True)
class Relationship(Record):
    id: str                          # "rel:<sha256(subject|predicate|object|seed_id), first 16 hex>"
    subject_id: str                  # asset id; for seed_is/prefix_contains_ip the subject is the seed id
    predicate: Predicate
    object_id: str
    evidence_ids: tuple[str, ...]
    seed_id: str
    depth: int                       # depth of object_id along this path


class ScopeDecision(str, Enum):
    EXPAND = "expand"     # record the object as a candidate and query further from it
    RECORD = "record"     # record the object as a candidate; enrich it, but never expand from it
    CONTEXT = "context"   # keep only as evidence on the subject; not a candidate
    DENY = "deny"         # outside the approved boundary; count it, do not record it


@dataclass(frozen=True)
class Decision(Record):
    decision: ScopeDecision
    reason: str


# --------------------------------------------------------------------------- assessment records

Dimension = Literal["ownership", "operational_control", "hosting", "service_association"]
Assessment = Literal["supported", "contradicted", "unresolved"]


@dataclass(frozen=True)
class Assertion(Record):
    id: str                                  # f"as:{asset_id}:{dimension}"
    asset_id: str
    dimension: Dimension
    value: str | None                        # the organization or provider the assessment is about
    assessment: Assessment
    supporting_evidence_ids: tuple[str, ...]
    contradicting_evidence_ids: tuple[str, ...]
    rationale: str


MatchStatus = Literal["matched", "unmatched", "indeterminate"]


@dataclass(frozen=True)
class InventoryMatch(Record):
    asset_id: str
    snapshot_id: str
    entry_id: str | None
    rule: Literal["exact", "prefix_containment", "domain_hierarchy", "none"]
    status: MatchStatus


Queue = Literal["known", "new", "unexplained", "third_party"]
Role = Literal["first_party", "third_party", "unresolved"]


@dataclass(frozen=True)
class Finding(Record):
    id: str                                  # f"fd:{asset_id}"
    asset_id: str
    asset_type: AssetType
    value: str
    queue: Queue
    role: Role
    inventory_match: InventoryMatch
    assertion_ids: tuple[str, ...]           # always the four dimensions, in Dimension order
    seed_id: str
    path: tuple[str, ...]                    # relationship ids from seed to this asset, shortest first-found path
    evidence_ids: tuple[str, ...]            # every evidence id on the path plus enrichment evidence for the asset
    first_observed: str | None
    last_observed: str | None
    flags: tuple[str, ...]                   # sorted; see docs/RULES.md "Flags"
    rank: float                              # higher = review first
    review_state: Literal["unreviewed"] = "unreviewed"


@dataclass
class Truncation(Record):
    limit: str                               # "max_hostnames", "max_addresses", "max_queries", "max_seconds"
    omitted: int                             # how many items were not recorded/queried because of it (best effort)
    detail: str


RunStatus = Literal["queued", "running", "pausing", "paused", "complete", "failed"]
