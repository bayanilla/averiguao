"""Attribution, reconciliation and findings (docs/RULES.md sections 3-6). Pure functions. Owner: graph/attribution agent."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .contracts import (Assertion, Asset, Evidence, Finding, InventoryMatch, InventorySnapshot, Relationship,
                        RunConfig)
from .store import Store


@dataclass
class Assessment:
    assertions: list[Assertion]
    matches: list[InventoryMatch]
    findings: list[Finding]


DIMENSIONS = ("ownership", "operational_control", "hosting", "service_association")
QUEUE_WEIGHT = {"new": 3.0, "unexplained": 2.0, "third_party": 1.0, "known": 0.0}
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "co.in",
                      "com.mx", "com.cn"}
SOURCES = ("ct", "dns", "rdap", "internetdb")
EMPTY_BASELINE_LABEL = "empty baseline"


# --------------------------------------------------------------------------- small helpers

def registrable_base(name: str) -> str:
    """Last two labels, or last three when the last two are a known two-level suffix."""
    labels = name.strip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _collapse(s: str) -> str:
    return " ".join(str(s).split()).casefold()


def org_matches(org_names: Iterable[str], rdap: dict[str, Any]) -> str | None:
    """Return the configured org name that matches the RDAP record (RULES 3), else None."""
    fields: list[str] = []
    fields += [str(x) for x in rdap.get("org_names") or [] if x]
    if rdap.get("network_name"):
        fields.append(str(rdap["network_name"]))
    fields += [str(x) for x in rdap.get("entity_handles") or [] if x]
    if rdap.get("handle"):
        fields.append(str(rdap["handle"]))
    norm_fields = [_collapse(f) for f in fields]
    for name in org_names:
        n = _collapse(name)
        if not n:
            continue
        pat = re.compile(r"(?<![0-9a-z])" + re.escape(n) + r"(?![0-9a-z])")
        for f in norm_fields:
            if f == n or pat.search(f):
                return name
    return None


def rdap_org(rdap: dict[str, Any]) -> str | None:
    names = [x for x in rdap.get("org_names") or [] if x]
    if names:
        return str(names[0])
    return rdap.get("network_name") or None


def _status(ev: Evidence) -> str:
    return str(ev.data.get("status") or "ok") if isinstance(ev.data, dict) else "ok"


def _is_ok(ev: Evidence) -> bool:
    return _status(ev) == "ok"


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _uniq(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(i for i in items if i))


def _ip(value: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


# --------------------------------------------------------------------------- context index

class _Ctx:
    def __init__(self, config: RunConfig, assets: list[dict[str, Any]], relationships: list[Relationship],
                 evidence: list[Evidence]):
        from .scope import ScopePolicy
        self.config = config
        self.policy = ScopePolicy(config)
        self.seeds = {s.id: s for s in config.seeds}
        self.domain_seed_ids = {s.value: s.id for s in config.seeds if s.type == "domain"}
        self.ev = {e.id: e for e in evidence}
        self.ev_order = {e.id: i for i, e in enumerate(evidence)}
        self.rels = {r.id: r for r in relationships}
        self.rels_by_object: dict[str, list[Relationship]] = {}
        self.rels_by_subject: dict[str, list[Relationship]] = {}
        for r in relationships:
            self.rels_by_object.setdefault(r.object_id, []).append(r)
            self.rels_by_subject.setdefault(r.subject_id, []).append(r)
        self.asset_rows = {self._asset(row).id: row for row in assets}
        self.by_query: dict[tuple[str, str], list[Evidence]] = {}
        self.rdap_ok: list[tuple[Evidence, list[ipaddress.IPv4Network]]] = []
        self.dns_ok: list[Evidence] = []
        for e in evidence:
            self.by_query.setdefault((e.source, e.query), []).append(e)
            if e.source == "rdap" and _is_ok(e):
                nets = []
                for c in e.data.get("cidrs") or []:
                    try:
                        net = ipaddress.ip_network(str(c), strict=False)
                    except ValueError:
                        continue
                    if isinstance(net, ipaddress.IPv4Network):
                        nets.append(net)
                self.rdap_ok.append((e, nets))
            if e.source == "dns" and _is_ok(e):
                self.dns_ok.append(e)

    @staticmethod
    def _asset(row: dict[str, Any]) -> Asset:
        a = row["asset"]
        return a if isinstance(a, Asset) else Asset(**a)

    def in_scope(self, name: str) -> str | None:
        return self.policy.in_scope_domain(name)

    def latest(self, evs: list[Evidence]) -> Evidence | None:
        if not evs:
            return None
        return max(evs, key=lambda e: (e.observed_at or "", self.ev_order.get(e.id, 0)))

    def rdap_for(self, ip: str) -> Evidence | None:
        """RDAP evidence for an ip: its own ok lookup (latest), else the most specific cached network containing it."""
        own = [e for e in self.by_query.get(("rdap", ip), []) if _is_ok(e)]
        if own:
            return self.latest(own)
        addr = _ip(ip)
        if addr is None:
            return None
        best: tuple[int, int, Evidence] | None = None
        for e, nets in self.rdap_ok:
            for net in nets:
                if addr in net:
                    key = (-net.prefixlen, self.ev_order.get(e.id, 0))
                    if best is None or key < best[:2]:
                        best = (key[0], key[1], e)
        return best[2] if best else None

    def final_cname(self, ev: Evidence) -> str | None:
        cnames = ev.data.get("cnames") or []
        return str(cnames[-1]).lower().rstrip(".") if cnames else None

    def external_cname(self, ev: Evidence) -> str | None:
        """Registrable base of the final CNAME target when it is outside the approved domains, else None."""
        final = self.final_cname(ev)
        if final and self.in_scope(final) is None:
            return registrable_base(final)
        return None

    def path(self, aid: str) -> tuple[str, ...]:
        chain: list[str] = []
        seen: set[str] = set()
        cur = aid
        while True:
            row = self.asset_rows.get(cur)
            rid = row.get("path_relationship_id") if row else None
            if not rid or rid in seen or rid not in self.rels:
                break
            seen.add(rid)
            chain.append(rid)
            subj = self.rels[rid].subject_id
            if subj in self.seeds or subj == cur:
                break
            cur = subj
        return tuple(reversed(chain))


# --------------------------------------------------------------------------- assertions

def _assertion(aid: str, dim: str, value: str | None, assessment: str, sup: Iterable[str], con: Iterable[str],
               rationale: str) -> Assertion:
    return Assertion(id=f"as:{aid}:{dim}", asset_id=aid, dimension=dim, value=value,  # type: ignore[arg-type]
                     assessment=assessment, supporting_evidence_ids=_uniq(sup),  # type: ignore[arg-type]
                     contradicting_evidence_ids=_uniq(con), rationale=rationale)


def _hostname_assertions(ctx: _Ctx, a: Asset) -> tuple[list[Assertion], set[str], list[str]]:
    """Returns (assertions, flags, extra evidence ids that belong to the finding)."""
    flags: set[str] = set()
    out: list[Assertion] = []
    name = a.value
    dom = ctx.in_scope(name)

    # ownership
    if dom is not None:
        sid = ctx.domain_seed_ids.get(dom)
        seed = ctx.seeds.get(sid) if sid else None
        ev_ids = [f"ev:seed:{sid.split(':', 1)[1]}"] if sid else []
        ref = seed.approval_ref if seed else ""
        out.append(_assertion(a.id, "ownership", dom, "supported", ev_ids, [],
                              f"{name} is within approved domain {dom} (approval: {ref})."))
    else:
        out.append(_assertion(a.id, "ownership", None, "unresolved", [], [],
                              f"{name} is not within an approved domain."))

    # operational control
    dns_evs = [e for e in ctx.by_query.get(("dns", name), []) if _is_ok(e)]
    latest = ctx.latest(dns_evs)
    ext = ctx.external_cname(latest) if latest else None
    if latest is not None and ext:
        out.append(_assertion(a.id, "operational_control", ext, "contradicted", [], [latest.id],
                              f"Latest DNS answer for {name} is a CNAME chain ending at "
                              f"{ctx.final_cname(latest)}, outside the approved domains (operator {ext})."))
    elif latest is not None and ctx.final_cname(latest):
        out.append(_assertion(a.id, "operational_control", None, "unresolved", [latest.id], [],
                              f"CNAME chain for {name} stays within the approved domains; control not established."))
    else:
        out.append(_assertion(a.id, "operational_control", None, "unresolved", [], [],
                              f"No external CNAME observed for {name}; control not established."))

    # hosting
    addresses = list(latest.data.get("addresses") or []) if latest else []
    if not addresses:
        out.append(_assertion(a.id, "hosting", None, "unresolved", [], [],
                              f"{name} has no DNS address; hosting provider unknown."))
    else:
        providers: dict[str, list[str]] = {}
        for ip in addresses:
            r = ctx.rdap_for(str(ip))
            org = rdap_org(r.data) if r else None
            if r is not None and org:
                providers.setdefault(org, []).append(r.id)
        if len(providers) == 1:
            org, ids = next(iter(providers.items()))
            out.append(_assertion(a.id, "hosting", org, "supported", [latest.id] + ids, [],
                                  f"All registered addresses of {name} belong to {org} (RDAP)."))
        elif len(providers) > 1:
            orgs = list(providers)
            flags.add("conflict")
            out.append(_assertion(a.id, "hosting", None, "unresolved", [latest.id] + providers[orgs[0]],
                                  [i for o in orgs[1:] for i in providers[o]],
                                  f"Addresses of {name} are registered to different providers: {', '.join(orgs)}."))
        else:
            out.append(_assertion(a.id, "hosting", None, "unresolved", [latest.id], [],
                                  f"No RDAP registration for the addresses of {name}."))

    # service association
    obs = [i for r in ctx.rels_by_object.get(a.id, []) for i in r.evidence_ids] + [e.id for e in dns_evs]
    if dom is not None:
        out.append(_assertion(a.id, "service_association", dom, "supported", obs, [],
                              f"In-scope name {name} observed in CT, DNS or InternetDB."))
    else:
        out.append(_assertion(a.id, "service_association", None, "unresolved", obs, [],
                              f"{name} is not within an approved domain."))
    return out, flags, [e.id for e in dns_evs]


def _ip_assertions(ctx: _Ctx, a: Asset) -> tuple[list[Assertion], set[str], list[str]]:
    flags: set[str] = set()
    out: list[Assertion] = []
    ip = a.value
    rd = ctx.rdap_for(ip)
    org = rdap_org(rd.data) if rd else None
    extra: list[str] = [rd.id] if rd else []

    # ownership
    if rd is None:
        out.append(_assertion(a.id, "ownership", None, "unresolved", [], [], f"No RDAP registration for {ip}."))
    elif not ctx.config.org_names:
        out.append(_assertion(a.id, "ownership", None, "unresolved", [rd.id], [],
                              "No organization names configured; ownership cannot be established."))
    else:
        matched = org_matches(ctx.config.org_names, rd.data)
        if matched:
            out.append(_assertion(a.id, "ownership", matched, "supported", [rd.id], [],
                                  f"RDAP registration of {ip} names the organization ({matched})."))
        else:
            value = org or rd.data.get("network_name")
            out.append(_assertion(a.id, "ownership", value, "contradicted", [], [rd.id],
                                  f"RDAP registration of {ip} names {value}, not a configured organization."))

    # operational control: every DNS observation that resolved to this ip
    paths = [e for e in ctx.dns_ok if ip in [str(x) for x in e.data.get("addresses") or []]]
    external = [(e, ctx.external_cname(e)) for e in paths]
    ext_evs = [(e, op) for e, op in external if op]
    int_evs = [e for e, op in external if not op]
    if paths and ext_evs and not int_evs:
        op = ext_evs[0][1]
        out.append(_assertion(a.id, "operational_control", op, "contradicted", [], [e.id for e, _ in ext_evs],
                              f"Every hostname path to {ip} passes through an external CNAME ({op})."))
    elif ext_evs and int_evs:
        flags.add("conflict")
        out.append(_assertion(a.id, "operational_control", None, "unresolved", [e.id for e in int_evs],
                              [e.id for e, _ in ext_evs],
                              f"Some hostname paths to {ip} pass through an external CNAME and some do not."))
    else:
        out.append(_assertion(a.id, "operational_control", None, "unresolved", [], [],
                              f"No evidence of who operates {ip}; address registration alone never supports control."))

    # hosting
    if rd is not None and org:
        out.append(_assertion(a.id, "hosting", org, "supported", [rd.id], [], f"{ip} is registered to {org} (RDAP)."))
    else:
        out.append(_assertion(a.id, "hosting", None, "unresolved", [rd.id] if rd else [], [],
                              f"No RDAP registration naming a provider for {ip}."))

    # service association
    sup: list[str] = []
    for r in ctx.rels_by_object.get(a.id, []):
        if r.predicate == "hostname_resolves_to_ip":
            subj_value = r.subject_id.split(":", 1)[1] if ":" in r.subject_id else r.subject_id
            if ctx.in_scope(subj_value) is not None:
                sup += list(r.evidence_ids)
    for r in ctx.rels_by_subject.get(a.id, []):
        if r.predicate == "ip_reports_hostname":
            obj_value = r.object_id.split(":", 1)[1]
            if ctx.in_scope(obj_value) is not None:
                sup += list(r.evidence_ids)
    if sup:
        out.append(_assertion(a.id, "service_association", None, "supported", sup, [],
                              f"{ip} is reached from an in-scope name via DNS or reports one in InternetDB."))
    else:
        out.append(_assertion(a.id, "service_association", None, "unresolved", [], [],
                              f"No in-scope name is associated with {ip}."))

    extra += [e.id for e in ctx.by_query.get(("internetdb", ip), [])]
    extra += [e.id for e in ctx.by_query.get(("rdap", ip), [])]
    return out, flags, extra


# --------------------------------------------------------------------------- reconciliation

def reconcile(a: Asset, snapshot: InventorySnapshot, prefix_containment: bool,
              domain_hierarchy: bool) -> InventoryMatch:
    entries = list(snapshot.entries)

    def m(entry_id: str | None, rule: str, status: str) -> InventoryMatch:
        return InventoryMatch(asset_id=a.id, snapshot_id=snapshot.id, entry_id=entry_id,  # type: ignore[arg-type]
                              rule=rule, status=status)  # type: ignore[arg-type]

    if a.type == "ip":
        addr = _ip(a.value)
        for e in entries:
            if e.kind == "ip" and e.value == a.value:
                return m(e.id, "exact", "matched")
            if e.kind == "cidr" and e.value.endswith("/32") and e.value[:-3] == a.value:
                return m(e.id, "exact", "matched")
        best = None
        if addr is not None:
            for e in entries:
                if e.kind != "cidr":
                    continue
                try:
                    net = ipaddress.ip_network(e.value, strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network) and addr in net:
                    if best is None or net.prefixlen > best[0]:
                        best = (net.prefixlen, e)
        if best:
            return m(best[1].id, "prefix_containment", "matched" if prefix_containment else "indeterminate")
    else:
        name = a.value
        for e in entries:
            if e.kind == "hostname" and e.value == name:
                return m(e.id, "exact", "matched")
        best = None
        for e in entries:
            if e.kind == "domain_tree" and (name == e.value or name.endswith("." + e.value)):
                depth = e.value.count(".")
                if best is None or depth > best[0]:
                    best = (depth, e)
        if best:
            return m(best[1].id, "domain_hierarchy", "matched" if domain_hierarchy else "indeterminate")
    return m(None, "none", "unmatched")


def _queue(match: InventoryMatch, role: str) -> str:
    if match.status == "matched":
        return "known"
    if match.status == "indeterminate":
        return "unexplained"
    if role == "first_party":
        return "new"
    if role == "third_party":
        return "third_party"
    return "unexplained"


def _role(by_dim: dict[str, Assertion]) -> str:
    if by_dim["operational_control"].assessment == "contradicted":
        return "third_party"
    if by_dim["ownership"].assessment == "supported" or by_dim["operational_control"].assessment == "supported":
        return "first_party"
    return "unresolved"


# --------------------------------------------------------------------------- assess

def assess(config: RunConfig, assets: list[dict[str, Any]], relationships: list[Relationship],
           evidence: list[Evidence], snapshot: InventorySnapshot, *, completed_at: str,
           truncated: bool, source_errors: dict[str, list[str]] | None = None) -> Assessment:
    """assets: Store.assets() rows. source_errors: asset_id -> evidence ids of failed source calls about it."""
    ctx = _Ctx(config, assets, relationships, evidence)
    source_errors = source_errors or {}
    completed = _parse_ts(completed_at)
    assertions: list[Assertion] = []
    matches: list[InventoryMatch] = []
    findings: list[Finding] = []

    for row in assets:
        a = ctx._asset(row)
        if a.type not in ("hostname", "ip"):
            continue
        if a.type == "hostname":
            asrts, flags, extra = _hostname_assertions(ctx, a)
        else:
            asrts, flags, extra = _ip_assertions(ctx, a)
        by_dim = {x.dimension: x for x in asrts}
        role = _role(by_dim)
        match = reconcile(a, snapshot, config.match_rules.prefix_containment, config.match_rules.domain_hierarchy)
        queue = _queue(match, role)

        path = ctx.path(a.id)
        errs = list(source_errors.get(a.id, []))
        ev_ids = _uniq([i for rid in path for i in ctx.rels[rid].evidence_ids]
                       + [i for r in ctx.rels_by_object.get(a.id, []) for i in r.evidence_ids]
                       + extra + errs)
        evs = [ctx.ev[i] for i in ev_ids if i in ctx.ev]

        if match.status == "indeterminate":
            flags.add("inventory_match_indeterminate")
        if errs:
            flags.add("source_error")
        if truncated:
            flags.add("truncated_run")
        dns_q = ctx.by_query.get(("dns", a.value), []) if a.type == "hostname" else []
        if any(_status(e) == "no_record" for e in dns_q):
            flags.add("no_resolution")
        ok_evs = [e for e in evs if _is_ok(e) and e.source != "scope"]  # seed approval is not an observation
        observations = [e for e in ok_evs if e.source in ("ct", "dns", "internetdb")]
        if completed is not None and observations:
            ends = [_parse_ts(e.valid_to) for e in observations]
            if all(t is not None and t < completed for t in ends):
                flags.add("stale_evidence")
        idb = [e for e in ctx.by_query.get(("internetdb", a.value), []) if _is_ok(e)] if a.type == "ip" else []
        vulns = any(e.data.get("vulns") for e in idb)
        ports = any(e.data.get("ports") for e in idb)
        if vulns:
            flags.add("potential_vulns")

        distinct_sources = len({e.source for e in ok_evs})
        rank = QUEUE_WEIGHT[queue] + 0.1 * distinct_sources + (0.2 if vulns else 0.0) + (0.1 if ports else 0.0) \
            - (0.3 if "stale_evidence" in flags else 0.0)
        observed = sorted(e.observed_at for e in evs if e.observed_at)
        assertion_ids = tuple(f"as:{a.id}:{d}" for d in DIMENSIONS)

        assertions.extend(by_dim[d] for d in DIMENSIONS)
        matches.append(match)
        findings.append(Finding(
            id=f"fd:{a.id}", asset_id=a.id, asset_type=a.type, value=a.value, queue=queue,  # type: ignore[arg-type]
            role=role, inventory_match=match, assertion_ids=assertion_ids,  # type: ignore[arg-type]
            seed_id=str(row.get("seed_id") or ""), path=path, evidence_ids=ev_ids,
            first_observed=observed[0] if observed else None, last_observed=observed[-1] if observed else None,
            flags=tuple(sorted(flags)), rank=round(rank, 4)))

    findings.sort(key=lambda f: (-f.rank, f.value))
    return Assessment(assertions=assertions, matches=matches, findings=findings)


def _empty_snapshot() -> InventorySnapshot:
    try:
        from .scope import parse_inventory
        return parse_inventory("", label=EMPTY_BASELINE_LABEL)
    except Exception:  # noqa: BLE001 - fall back to a locally built empty snapshot
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        sid = "snap:" + hashlib.sha256(b"").hexdigest()[:16]
        return InventorySnapshot(id=sid, as_of=now, imported_at=now, label=EMPTY_BASELINE_LABEL, entries=())


def assess_run(store: Store, run_id: str) -> None:
    """Load everything for the run, use the current inventory snapshot (creating the empty baseline snapshot and
    the run flag 'empty_inventory' if none exists), assess, and save_assessment."""
    from .scope import run_config_from_dict
    run = store.run(run_id)
    if run is None:
        raise ValueError(f"unknown run {run_id}")
    cfg = run["config"]
    config = cfg if isinstance(cfg, RunConfig) else run_config_from_dict(cfg)
    snapshot = store.current_snapshot()
    if snapshot is None:
        snapshot = _empty_snapshot()
        store.save_snapshot(snapshot)
        store.add_run_flag(run_id, "empty_inventory")
    assets = store.assets(run_id)
    relationships = store.relationships(run_id)
    evidence = store.evidence(run_id)
    values = {}
    for row in assets:
        a = _Ctx._asset(row)
        if a.type in ("hostname", "ip"):
            values.setdefault(a.value, []).append(a.id)
    source_errors: dict[str, list[str]] = {}
    for e in evidence:
        if isinstance(e.data, dict) and e.data.get("status") == "error":
            for aid in values.get(e.query, []):
                source_errors.setdefault(aid, []).append(e.id)
    completed_at = run.get("finished_at") or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    result = assess(config, assets, relationships, evidence, snapshot, completed_at=completed_at,
                    truncated=bool(run.get("truncated")), source_errors=source_errors)
    store.save_assessment(run_id, snapshot.id, result.assertions, result.matches, result.findings)
