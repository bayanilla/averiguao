"""Scope guard: parse and validate seeds, run configuration and inventory; decide what discovery may record.

Owner: scope agent. See docs/RULES.md sections 1 and 2.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from .contracts import (
    HARD_MAX_PREFIX_ADDRESSES,
    Decision,
    InventoryEntry,
    InventorySnapshot,
    Limits,
    MatchRules,
    RunConfig,
    ScopeDecision,
    Seed,
)


class ScopeError(ValueError):
    """Raised for invalid input. The message is shown to the user and names the line or field."""


# --------------------------------------------------------------------------- constants

MAX_SEEDS = 50
MAX_APPROVAL_REF = 200
MAX_SCOPE_VERSION = 100
MAX_LABEL = 200
MAX_ORG_NAMES = 20
ORG_NAME_MIN, ORG_NAME_MAX = 2, 100
MAX_INVENTORY_ENTRIES = 10_000
MAX_INVENTORY_LABEL = 500

# IANA IPv4 special-purpose registry (plus multicast and the reserved class E space). Built explicitly instead of
# relying on ``is_global`` of a network, which only inspects the network and broadcast addresses.
SPECIAL_PURPOSE_NETWORKS: tuple[tuple[ipaddress.IPv4Network, str], ...] = tuple(
    (ipaddress.IPv4Network(cidr), name) for cidr, name in (
        ("0.0.0.0/8", "this network"),
        ("10.0.0.0/8", "private use"),
        ("100.64.0.0/10", "shared address space"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link local"),
        ("172.16.0.0/12", "private use"),
        ("192.0.0.0/24", "IETF protocol assignments"),
        ("192.0.2.0/24", "documentation (TEST-NET-1)"),
        ("192.88.99.0/24", "deprecated 6to4 relay anycast"),
        ("192.168.0.0/16", "private use"),
        ("198.18.0.0/15", "benchmarking"),
        ("198.51.100.0/24", "documentation (TEST-NET-2)"),
        ("203.0.113.0/24", "documentation (TEST-NET-3)"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
        ("255.255.255.255/32", "limited broadcast"),
    )
)

DOCUMENTATION_NETWORKS: frozenset[ipaddress.IPv4Network] = frozenset(
    ipaddress.IPv4Network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

PUBLIC_SUFFIXES: frozenset[str] = frozenset("""
com net org edu gov io co uk co.uk org.uk ac.uk gov.uk com.au net.au de fr jp co.jp br com.br in co.in es it nl eu
ca us mx com.mx pr cn com.cn ru info biz app dev cloud test example invalid localhost
""".split())

INVENTORY_HEADERS = frozenset({"value", "ip", "ip_or_cidr", "cidr", "network", "asset"})

LIMIT_FIELDS = ("max_depth", "max_hostnames", "max_addresses", "max_queries", "max_seconds", "max_prefix_addresses")
LIMIT_MAX = {
    "max_depth": 3,
    "max_seconds": 86_400,
    "max_queries": 200_000,
    "max_prefix_addresses": HARD_MAX_PREFIX_ADDRESSES,
}
LIMIT_MIN = {"max_depth": 1}

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")


# --------------------------------------------------------------------------- helpers

def _special_overlap(net: ipaddress.IPv4Network, allow_documentation_ranges: bool) -> str | None:
    for block, name in SPECIAL_PURPOSE_NETWORKS:
        if allow_documentation_ranges and block in DOCUMENTATION_NETWORKS:
            continue
        if net.overlaps(block):
            return f"{block} ({name})"
    return None


def _parse_ipv4(text: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text)
    except ValueError as exc:
        raise ScopeError(f"'{text}' is not a valid IPv4 address") from exc


def _parse_cidr(text: str) -> ipaddress.IPv4Network:
    """Strict IPv4 CIDR: integer prefix length, host bits must be zero."""
    m = _CIDR_RE.match(text)
    if not m:
        raise ScopeError(f"'{text}' is not a valid IPv4 CIDR (expected a.b.c.d/len)")
    addr = _parse_ipv4(m.group(1))
    plen = int(m.group(2))
    if plen > 32:
        raise ScopeError(f"'{text}' has an invalid prefix length /{plen}")
    net = ipaddress.IPv4Network((addr, plen), strict=False)
    if net.network_address != addr:
        raise ScopeError(f"'{text}' has host bits set; use {net} for the whole network")
    return net


def _check_ipv6(text: str) -> None:
    if ":" in text:
        raise ScopeError(f"'{text}' looks like IPv6; only IPv4 is supported")


def _is_ip_like(text: str) -> bool:
    return bool(_IPV4_RE.match(text) or _CIDR_RE.match(text) or "/" in text)


def normalize_hostname(name: str) -> str | None:
    """Lowercase, strip trailing dot, IDNA-encode. Return None if not a valid hostname. '*.x' is returned unchanged
    (callers decide what to do with wildcards)."""
    if not isinstance(name, str):
        return None
    text = name.strip()
    if text.startswith("*."):
        base = normalize_hostname(text[2:])
        return None if base is None or base.startswith("*") else "*." + base
    if text.endswith("."):
        text = text[:-1]
    if not text or "*" in text or any(c.isspace() for c in text):
        return None
    try:
        encoded = text.lower().encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    encoded = encoded.lower()
    if len(encoded) > 253:
        return None
    labels = encoded.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL_RE.match(label) for label in labels):
        return None
    last = labels[-1]
    if not (last.isalpha() or last.startswith("xn--")):
        return None
    return encoded


def _is_under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_time(value: str) -> str:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ScopeError(f"as_of '{value}' is not an ISO-8601 date/time") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- seeds

def _parse_seed_value(text: str, max_prefix_addresses: int,
                      allow_documentation_ranges: bool) -> tuple[str, str]:
    _check_ipv6(text)
    if _is_ip_like(text):
        if "/" in text:
            net = _parse_cidr(text)
            overlap = _special_overlap(net, allow_documentation_ranges)
            if overlap:
                raise ScopeError(f"{net} overlaps non-global range {overlap}")
            if net.num_addresses > max_prefix_addresses:
                raise ScopeError(f"{net} has {net.num_addresses} addresses; the limit is {max_prefix_addresses}")
            if net.prefixlen == 32:
                return "ip", str(net.network_address)
            return "prefix", str(net)
        addr = _parse_ipv4(text)
        overlap = _special_overlap(ipaddress.IPv4Network(addr), allow_documentation_ranges)
        if overlap:
            raise ScopeError(f"{addr} is in non-global range {overlap}")
        return "ip", str(addr)
    if "*" in text:
        raise ScopeError(f"'{text}': wildcards are not allowed in seeds; give the domain itself")
    domain = normalize_hostname(text)
    if domain is None:
        raise ScopeError(f"'{text}' is not a valid domain name, IPv4 address or IPv4 CIDR")
    if domain in PUBLIC_SUFFIXES:
        raise ScopeError(f"'{domain}' is a public suffix, not an organization's domain")
    return "domain", domain


def _validate_approval_ref(approval_ref: Any) -> str:
    if not isinstance(approval_ref, str) or not approval_ref.strip():
        raise ScopeError("approval_ref is required (ticket, letter or contract that approves this scope)")
    ref = approval_ref.strip()
    if len(ref) > MAX_APPROVAL_REF:
        raise ScopeError(f"approval_ref is longer than {MAX_APPROVAL_REF} characters")
    return ref


def _validate_max_prefix(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ScopeError("max_prefix_addresses must be a positive integer")
    if value > HARD_MAX_PREFIX_ADDRESSES:
        raise ScopeError(f"max_prefix_addresses cannot exceed {HARD_MAX_PREFIX_ADDRESSES}")
    return value


def parse_seeds(text: str, approval_ref: str, scope_version: str = "1",
                max_prefix_addresses: int = 4096, *,
                allow_documentation_ranges: bool = False) -> tuple[Seed, ...]:
    """Parse one seed per line (blank lines and '#' comments ignored). Raises ScopeError."""
    if not isinstance(text, str):
        raise ScopeError("seeds must be text with one seed per line")
    ref = _validate_approval_ref(approval_ref)
    if not isinstance(scope_version, str) or not scope_version.strip():
        raise ScopeError("scope_version must be a non-empty string")
    version = scope_version.strip()
    if len(version) > MAX_SCOPE_VERSION:
        raise ScopeError(f"scope_version is longer than {MAX_SCOPE_VERSION} characters")
    limit = _validate_max_prefix(max_prefix_addresses)

    seeds: list[Seed] = []
    seen: set[tuple[str, str]] = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            kind, value = _parse_seed_value(line, limit, allow_documentation_ranges)
        except ScopeError as exc:
            raise ScopeError(f"Seed line {number}: {exc}") from None
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        if len(seeds) >= MAX_SEEDS:
            raise ScopeError(f"Seed line {number}: more than {MAX_SEEDS} seeds")
        seeds.append(Seed(id=f"seed:{len(seeds) + 1}", type=kind, value=value,  # type: ignore[arg-type]
                          approval_ref=ref, scope_version=version))
    if not seeds:
        raise ScopeError("At least one seed is required")
    return tuple(seeds)


# --------------------------------------------------------------------------- run configuration

def _parse_org_names(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        items: list[Any] = value.split(",")
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ScopeError("org_names must be a list or a comma-separated string")
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str):
            raise ScopeError("org_names entries must be strings")
        name = " ".join(item.split())
        if not name:
            continue
        if not ORG_NAME_MIN <= len(name) <= ORG_NAME_MAX:
            raise ScopeError(f"org_names entry '{name[:40]}' must be {ORG_NAME_MIN}-{ORG_NAME_MAX} characters")
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(name)
    if len(result) > MAX_ORG_NAMES:
        raise ScopeError(f"At most {MAX_ORG_NAMES} org_names are allowed")
    return tuple(result)


def _parse_limits(value: Any) -> Limits:
    if value is None:
        return Limits()
    if not isinstance(value, dict):
        raise ScopeError("limits must be an object")
    unknown = sorted(set(value) - set(LIMIT_FIELDS))
    if unknown:
        raise ScopeError(f"Unknown limits: {', '.join(map(str, unknown))}")
    values: dict[str, int] = {}
    for key, raw in value.items():
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ScopeError(f"limits.{key} must be an integer")
        lo = LIMIT_MIN.get(key, 1)
        hi = LIMIT_MAX.get(key)
        if raw < lo or (hi is not None and raw > hi):
            bound = f"between {lo} and {hi}" if hi is not None else f"at least {lo}"
            raise ScopeError(f"limits.{key} must be {bound}")
        values[key] = raw
    return Limits(**values)


def _parse_match_rules(value: Any) -> MatchRules:
    if value is None:
        return MatchRules()
    if not isinstance(value, dict):
        raise ScopeError("match_rules must be an object")
    unknown = sorted(set(value) - {"exact", "prefix_containment", "domain_hierarchy"})
    if unknown:
        raise ScopeError(f"Unknown match_rules: {', '.join(map(str, unknown))}")
    for key, raw in value.items():
        if not isinstance(raw, bool):
            raise ScopeError(f"match_rules.{key} must be true or false")
    if value.get("exact", True) is not True:
        raise ScopeError("match_rules.exact cannot be disabled")
    return MatchRules(prefix_containment=value.get("prefix_containment", True),
                      domain_hierarchy=value.get("domain_hierarchy", False))


def parse_run_config(body: dict[str, Any], *, allow_documentation_ranges: bool = False) -> RunConfig:
    """Build a RunConfig from the API/CLI JSON shape:
    {"seeds": "multi-line text", "approval_ref": str, "scope_version": str?, "org_names": [str] | "comma,separated",
     "label": str?, "limits": {Limits fields}?, "match_rules": {"prefix_containment": bool, "domain_hierarchy": bool}?}
    Raises ScopeError."""
    if not isinstance(body, dict):
        raise ScopeError("Run configuration must be an object")
    limits = _parse_limits(body.get("limits"))
    seeds_text = body.get("seeds")
    if isinstance(seeds_text, (list, tuple)):
        if not all(isinstance(s, str) for s in seeds_text):
            raise ScopeError("seeds must be text with one seed per line")
        seeds_text = "\n".join(seeds_text)
    if not isinstance(seeds_text, str):
        raise ScopeError("seeds must be text with one seed per line")
    scope_version = body.get("scope_version")
    if scope_version is None or (isinstance(scope_version, str) and not scope_version.strip()):
        scope_version = "1"
    seeds = parse_seeds(seeds_text, body.get("approval_ref"), scope_version,  # type: ignore[arg-type]
                        limits.max_prefix_addresses, allow_documentation_ranges=allow_documentation_ranges)
    label = body.get("label") or ""
    if not isinstance(label, str):
        raise ScopeError("label must be a string")
    label = label.strip()
    if len(label) > MAX_LABEL:
        raise ScopeError(f"label is longer than {MAX_LABEL} characters")
    return RunConfig(seeds=seeds, org_names=_parse_org_names(body.get("org_names")), limits=limits,
                     match_rules=_parse_match_rules(body.get("match_rules")), label=label)


def run_config_from_dict(data: dict[str, Any]) -> RunConfig:
    """Inverse of RunConfig.to_dict() (used when loading a stored run). No re-validation of limits needed."""
    return RunConfig(
        seeds=tuple(Seed(**s) for s in data["seeds"]),
        org_names=tuple(data.get("org_names") or ()),
        limits=Limits(**(data.get("limits") or {})),
        match_rules=MatchRules(**(data.get("match_rules") or {})),
        label=data.get("label", ""),
    )


# --------------------------------------------------------------------------- inventory

def _parse_inventory_value(text: str) -> tuple[str, str]:
    _check_ipv6(text)
    if _is_ip_like(text):
        if "/" in text:
            return "cidr", str(_parse_cidr(text))
        return "ip", str(_parse_ipv4(text))
    norm = normalize_hostname(text)
    if norm is None:
        raise ScopeError(f"'{text}' is not an IPv4 address, IPv4 CIDR, hostname or *.domain")
    if norm.startswith("*."):
        base = norm[2:]
        if base in PUBLIC_SUFFIXES:
            raise ScopeError(f"'{text}' would cover a whole public suffix")
        return "domain_tree", base
    return "hostname", norm


def parse_inventory(csv_text: str, label: str = "", as_of: str | None = None) -> InventorySnapshot:
    """Parse inventory CSV into a new snapshot (RULES.md 1, Inventory). Raises ScopeError."""
    if not isinstance(csv_text, str):
        raise ScopeError("Inventory must be CSV text")
    imported_at = _now_utc()
    as_of_value = imported_at if as_of is None or not str(as_of).strip() else _normalize_time(str(as_of))
    if csv_text.startswith("﻿"):
        csv_text = csv_text[1:]

    entries: list[InventoryEntry] = []
    seen: set[tuple[str, str]] = set()
    first_row = True
    reader = csv.reader(io.StringIO(csv_text))
    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            raise ScopeError(f"Inventory line {reader.line_num}: malformed CSV ({exc})") from None
        number = reader.line_num
        if not row or not any(cell.strip() for cell in row):
            continue
        value = row[0].strip()
        if first_row:
            first_row = False
            if value.lower() in INVENTORY_HEADERS:
                continue
        if value.startswith("#"):
            continue
        if len(row) > 2 and any(cell.strip() for cell in row[2:]):
            raise ScopeError(f"Inventory line {number}: expected 'value,label' (found {len(row)} columns)")
        if not value:
            raise ScopeError(f"Inventory line {number}: value is empty")
        try:
            kind, norm = _parse_inventory_value(value)
        except ScopeError as exc:
            raise ScopeError(f"Inventory line {number}: {exc}") from None
        entry_label = " ".join(row[1].split()) if len(row) > 1 else ""
        if len(entry_label) > MAX_INVENTORY_LABEL:
            raise ScopeError(f"Inventory line {number}: label is longer than {MAX_INVENTORY_LABEL} characters")
        if (kind, norm) in seen:
            continue
        seen.add((kind, norm))
        if len(entries) >= MAX_INVENTORY_ENTRIES:
            raise ScopeError(f"Inventory line {number}: more than {MAX_INVENTORY_ENTRIES:,} entries")
        entries.append(InventoryEntry(id=f"inv:{len(entries) + 1}", kind=kind,  # type: ignore[arg-type]
                                      value=norm, label=entry_label))

    digest = hashlib.sha256(
        "".join(f"{e.kind},{e.value},{e.label}\n" for e in entries).encode("utf-8")).hexdigest()
    return InventorySnapshot(id=f"snap:{digest[:16]}", as_of=as_of_value, imported_at=imported_at,
                             label=(label or "").strip(), entries=tuple(entries))


# --------------------------------------------------------------------------- policy

_HOSTNAME_PREDICATES = {"certificate_mentions_hostname", "ip_reports_hostname"}
_ALL_PREDICATES = _HOSTNAME_PREDICATES | {"hostname_resolves_to_ip", "prefix_contains_ip", "rdap_enrichment",
                                          "cname_target"}


class ScopePolicy:
    """Answers scope questions for one run. Pure; no I/O."""

    def __init__(self, config: RunConfig):
        self.config = config
        self.limits = config.limits
        # Longest first so in_scope_domain returns the most specific seed.
        self._domains = tuple(sorted({s.value for s in config.seeds if s.type == "domain"},
                                     key=lambda d: (-len(d), d)))

    def in_scope_domain(self, name: str) -> str | None:
        """Return the domain seed value that `name` equals or falls under, else None."""
        norm = normalize_hostname(name)
        if norm is None or norm.startswith("*."):
            return None
        for domain in self._domains:
            if _is_under(norm, domain):
                return domain
        return None

    def _depth_ok(self, depth: int) -> bool:
        return depth <= self.limits.max_depth

    def decide(self, predicate: str, object_value: str, depth: int) -> Decision:
        """Decision for recording `object_value` reached via `predicate` at `depth` (RULES.md 2 table).
        predicate is one of: "certificate_mentions_hostname", "hostname_resolves_to_ip", "ip_reports_hostname",
        "prefix_contains_ip", "rdap_enrichment", "cname_target"."""
        if predicate not in _ALL_PREDICATES:
            raise ValueError(f"unknown predicate {predicate!r}")
        if predicate == "rdap_enrichment":
            return Decision(ScopeDecision.CONTEXT, "enrichment_only")
        if predicate == "cname_target":
            return Decision(ScopeDecision.CONTEXT, "cname_context")
        if predicate == "certificate_mentions_hostname":
            if self.in_scope_domain(object_value) is None:
                return Decision(ScopeDecision.DENY, "ct_name_outside_approved_domains")
            if not self._depth_ok(depth):
                return Decision(ScopeDecision.DENY, "depth_limit")
            return Decision(ScopeDecision.EXPAND, "in_scope")
        if predicate == "ip_reports_hostname":
            if self.in_scope_domain(object_value) is None:
                return Decision(ScopeDecision.CONTEXT, "hostname_outside_approved_domains")
            if not self._depth_ok(depth):
                return Decision(ScopeDecision.DENY, "depth_limit")
            return Decision(ScopeDecision.RECORD, "in_scope")
        if predicate == "hostname_resolves_to_ip":
            if not self._depth_ok(depth):
                return Decision(ScopeDecision.DENY, "depth_limit")
            return Decision(ScopeDecision.RECORD, "in_scope")
        # prefix_contains_ip
        if not self._depth_ok(depth):
            return Decision(ScopeDecision.DENY, "depth_limit")
        return Decision(ScopeDecision.RECORD, "prefix_member")

    def prefix_addresses(self, seed: Seed) -> list[str]:
        """Every address of a prefix seed, in order."""
        if seed.type != "prefix":
            raise ValueError(f"{seed.id} is not a prefix seed")
        net = ipaddress.IPv4Network(seed.value, strict=True)
        if net.num_addresses > HARD_MAX_PREFIX_ADDRESSES:
            raise ValueError(f"{seed.value} exceeds the hard prefix limit")
        start = int(net.network_address)
        return [str(ipaddress.IPv4Address(start + i)) for i in range(net.num_addresses)]
