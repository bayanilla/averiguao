"""Bounded discovery engine (docs/RULES.md section 2). Owner: graph/attribution agent."""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from .contracts import (Asset, Connector, Evidence, Relationship, RunConfig, Seed, SourceName, SourceResult,
                        Truncation, asset_id)
from .store import Store

# Monotonic clock used for max_seconds; tests may replace it.
_clock = time.monotonic

DENY_CT_OUT_OF_SCOPE = "ct_name_outside_approved_domains"
DENY_DEPTH = "depth_limit"
DENY_INVALID_NAME = "invalid_name"
DENY_NON_GLOBAL = "non_global_address"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def evidence_id(source: str, query: str, source_record_id: str | None, retrieved_at: str,
                raw_sha256: str | None) -> str:
    """'ev:<sha256(source|query|source_record_id|retrieved_at|raw_sha256), first 16 hex>' (None -> empty)."""
    return "ev:" + _sha16(f"{source}|{query}|{source_record_id or ''}|{retrieved_at}|{raw_sha256 or ''}")


def relationship_id(subject_id: str, predicate: str, object_id: str, seed_id: str) -> str:
    return "rel:" + _sha16(f"{subject_id}|{predicate}|{object_id}|{seed_id}")


def seed_evidence_id(seed: Seed) -> str:
    return "ev:seed:" + seed.id.split(":", 1)[1]


def _load_config(run: dict[str, Any]) -> RunConfig:
    from .scope import run_config_from_dict
    cfg = run["config"]
    return cfg if isinstance(cfg, RunConfig) else run_config_from_dict(cfg)


def _normalize_name(name: str) -> str | None:
    from .scope import normalize_hostname
    try:
        return normalize_hostname(name)
    except Exception:  # defensive: a malformed source name is never fatal
        return None


class _Batch:
    """Everything one batch produces; committed in one store transaction."""

    def __init__(self, store: Store, run_id: str, config: RunConfig):
        self.store = store
        self.run_id = run_id
        self.config = config
        self.evidence: dict[str, Evidence] = {}
        self.assets: list[tuple[Asset, str, int, str | None]] = []
        self.new_asset_ids: set[str] = set()
        self.relationships: dict[str, Relationship] = {}
        self.tasks: list[tuple[str, str, str, int, str | None]] = []
        self.coverage: list[tuple[str, str, str, str]] = []
        self.queries = 0
        self.source_failures: dict[str, int] = {}
        self.out_of_scope: dict[str, int] = {}
        self.truncations: dict[str, Truncation] = {}
        self._counts = {"hostname": store.asset_count(run_id, "hostname"), "ip": store.asset_count(run_id, "ip")}

    # -- helpers
    def has_asset(self, aid: str) -> bool:
        return aid in self.new_asset_ids or self.store.has_asset(self.run_id, aid)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.setdefault(ev.id, ev)

    def deny(self, reason: str, n: int = 1) -> None:
        self.out_of_scope[reason] = self.out_of_scope.get(reason, 0) + n

    def fail(self, source: str) -> None:
        self.source_failures[source] = self.source_failures.get(source, 0) + 1

    def truncate(self, limit: str, detail: str) -> None:
        t = self.truncations.get(limit)
        if t is None:
            self.truncations[limit] = Truncation(limit=limit, omitted=1, detail=detail)
        else:
            t.omitted += 1

    def relate(self, subject: str, predicate: str, obj: str, ev_ids: list[str], seed_id: str, depth: int) -> str:
        rid = relationship_id(subject, predicate, obj, seed_id)
        old = self.relationships.get(rid)
        if old is None:
            self.relationships[rid] = Relationship(id=rid, subject_id=subject, predicate=predicate,  # type: ignore[arg-type]
                                                   object_id=obj, evidence_ids=tuple(dict.fromkeys(ev_ids)),
                                                   seed_id=seed_id, depth=depth)
        else:
            merged = tuple(dict.fromkeys(list(old.evidence_ids) + list(ev_ids)))
            self.relationships[rid] = Relationship(id=rid, subject_id=old.subject_id, predicate=old.predicate,
                                                   object_id=old.object_id, evidence_ids=merged,
                                                   seed_id=old.seed_id, depth=old.depth)
        return rid

    def new_asset(self, type_: str, value: str, seed_id: str, depth: int, rel_id: str | None,
                  enforce_limit: bool = True) -> bool:
        """Record a new asset. False when the hostname/address limit stops it (truncation counted)."""
        aid = asset_id(type_, value)  # type: ignore[arg-type]
        if enforce_limit:
            limit_name = "max_hostnames" if type_ == "hostname" else "max_addresses"
            limit = self.config.limits.max_hostnames if type_ == "hostname" else self.config.limits.max_addresses
            if self._counts.get(type_, 0) >= limit:
                self.truncate(limit_name, f"{limit_name} ({limit}) reached; further {type_}s were not recorded")
                return False
        self.assets.append((Asset(id=aid, type=type_, value=value), seed_id, depth, rel_id))  # type: ignore[arg-type]
        self.new_asset_ids.add(aid)
        if type_ in self._counts:
            self._counts[type_] += 1
        return True

    def reach(self, subject: str, predicate: str, type_: str, value: str, ev_ids: list[str], seed_id: str,
              depth: int, tasks: list[tuple[str, str]]) -> None:
        """Record subject -predicate-> type_:value. New assets obey limits and get `tasks`; existing assets only
        gain the relationship observation."""
        aid = asset_id(type_, value)  # type: ignore[arg-type]
        rid = relationship_id(subject, predicate, aid, seed_id)
        if self.has_asset(aid):
            self.relate(subject, predicate, aid, ev_ids, seed_id, depth)
            return
        if not self.new_asset(type_, value, seed_id, depth, rid):
            return
        self.relate(subject, predicate, aid, ev_ids, seed_id, depth)
        for source, query in tasks:
            self.tasks.append((source, query, seed_id, depth, aid))

    def commit(self, done_task_ids: list[int]) -> None:
        self.store.commit_batch(
            self.run_id, done_task_ids=done_task_ids, evidence=list(self.evidence.values()), assets=self.assets,
            relationships=list(self.relationships.values()), new_tasks=self.tasks, coverage=self.coverage,
            queries=self.queries, source_failures=self.source_failures, out_of_scope=self.out_of_scope,
            truncations=list(self.truncations.values()))


# --------------------------------------------------------------------------- evidence construction

def _result_evidence(res: SourceResult, query: str) -> Evidence:
    """One Evidence for a dns/rdap/internetdb result (any status)."""
    if res.status == "ok":
        data = dict(res.data)
    elif res.status == "error":
        data = {"status": "error", "error": res.error}
    else:
        data = {"status": "no_record"}
    record_id = None
    if res.source == "rdap" and res.status == "ok":
        record_id = res.data.get("handle")
    return Evidence(id=evidence_id(res.source, query, record_id, res.retrieved_at, res.raw_sha256), source=res.source,
                    query=query, source_url=res.source_url, raw_sha256=res.raw_sha256, observed_at=res.retrieved_at,
                    valid_from=None, valid_to=None, source_record_id=record_id, data=data)


def _cert_evidence(res: SourceResult, query: str, cert: dict[str, Any]) -> Evidence:
    data = dict(cert)
    data["query"] = query
    cid = cert.get("id")
    rid = None if cid is None else str(cid)
    return Evidence(id=evidence_id(res.source, query, rid, res.retrieved_at, res.raw_sha256), source="ct",
                    query=query, source_url=res.source_url, raw_sha256=res.raw_sha256, observed_at=res.retrieved_at,
                    valid_from=cert.get("not_before"), valid_to=cert.get("not_after"),
                    source_record_id=rid, data=data)


# --------------------------------------------------------------------------- seeding

def _seed(store: Store, run_id: str, config: RunConfig) -> None:
    from .scope import ScopePolicy
    batch = _Batch(store, run_id, config)
    now = _now_iso()
    policy = None
    for seed in config.seeds:
        ev = Evidence(id=seed_evidence_id(seed), source="scope", query=seed.value, source_url="", raw_sha256=None,
                      observed_at=now, valid_from=None, valid_to=None, source_record_id=seed.id,
                      data={"approval_ref": seed.approval_ref, "scope_version": seed.scope_version,
                            "seed_type": seed.type})
        batch.add_evidence(ev)
        if seed.type in ("domain", "ip"):
            aid = asset_id(seed.type, seed.value)
            rid = relationship_id(seed.id, "seed_is", aid, seed.id)
            if not batch.has_asset(aid):
                batch.new_asset(seed.type, seed.value, seed.id, 0, rid, enforce_limit=False)
            batch.relate(seed.id, "seed_is", aid, [ev.id], seed.id, 0)
            if seed.type == "domain":
                batch.tasks += [("ct", seed.value, seed.id, 0, aid), ("dns", seed.value, seed.id, 0, aid)]
            else:
                batch.tasks += [("rdap", seed.value, seed.id, 0, aid), ("internetdb", seed.value, seed.id, 0, aid)]
        else:  # prefix
            if policy is None:
                policy = ScopePolicy(config)
            net = ipaddress.ip_network(seed.value, strict=False)
            batch.tasks.append(("rdap", str(net.network_address), seed.id, 1, None))
            for ip in policy.prefix_addresses(seed):
                batch.tasks.append(("internetdb", ip, seed.id, 1, None))
    batch.commit([])


# --------------------------------------------------------------------------- result handling

class _Handler:
    def __init__(self, config: RunConfig):
        from .scope import ScopePolicy
        self.config = config
        self.policy = ScopePolicy(config)
        self.seeds = {s.id: s for s in config.seeds}
        self.domain_seed_values = {s.value for s in config.seeds if s.type == "domain"}
        self.prefix_nets = [ipaddress.ip_network(s.value, strict=False) for s in config.seeds if s.type == "prefix"]

    def in_prefix_seed(self, ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.prefix_nets)

    def in_scope(self, name: str) -> str | None:
        return self.policy.in_scope_domain(name)

    def apply(self, batch: _Batch, task: dict[str, Any], res: SourceResult | None) -> None:
        source, query, seed_id = task["source"], task["query"], task["seed_id"]
        depth, from_aid = int(task["depth"]), task["from_asset_id"]
        if res is None:  # RDAP cache hit: evidence already stored, nothing to query or record
            return
        is_prefix_member = source == "internetdb" and from_aid is None
        if res.status == "error":
            batch.fail(source)
        if source == "ct":
            self._ct(batch, res, query, seed_id, depth, from_aid)
            return
        if is_prefix_member or (source == "internetdb" and self.in_prefix_seed(query)):
            # every checked prefix address is listed in coverage, even when another seed's task queried it
            batch.coverage.append((query, source, res.status, res.retrieved_at))
            if is_prefix_member and res.status == "no_record":
                return
        ev = _result_evidence(res, query)
        batch.add_evidence(ev)
        if res.status != "ok":
            return
        if source == "dns":
            self._dns(batch, res, ev, seed_id, depth, from_aid)
        elif source == "internetdb":
            ip_aid = from_aid
            if is_prefix_member:
                ip_aid = asset_id("ip", query)
                rid = relationship_id(seed_id, "prefix_contains_ip", ip_aid, seed_id)
                if batch.has_asset(ip_aid):
                    batch.relate(seed_id, "prefix_contains_ip", ip_aid, [ev.id], seed_id, depth)
                elif batch.new_asset("ip", query, seed_id, depth, rid):
                    batch.relate(seed_id, "prefix_contains_ip", ip_aid, [ev.id], seed_id, depth)
                else:
                    return
            self._internetdb_hostnames(batch, res, ev, seed_id, depth, ip_aid)

    def _ct(self, batch: _Batch, res: SourceResult, query: str, seed_id: str, depth: int,
            from_aid: str | None) -> None:
        if res.status != "ok":
            batch.add_evidence(_result_evidence(res, query))
            return
        certs = res.data.get("certificates") or []
        if not certs:
            batch.add_evidence(Evidence(
                id=evidence_id(res.source, query, None, res.retrieved_at, res.raw_sha256), source="ct", query=query,
                source_url=res.source_url, raw_sha256=res.raw_sha256, observed_at=res.retrieved_at, valid_from=None,
                valid_to=None, source_record_id=None, data={"certificates": [], "query": query}))
            return
        subject = from_aid or asset_id("domain", query)
        new_depth = depth + 1
        denied: dict[str, set[str]] = {}
        for cert in certs:
            ev = _cert_evidence(res, query, cert)
            batch.add_evidence(ev)
            for raw in cert.get("names") or []:
                name = str(raw).strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                norm = _normalize_name(name)
                if norm is None or norm.startswith("*"):
                    denied.setdefault(DENY_INVALID_NAME, set()).add(name)
                    continue
                if norm == query or norm in self.domain_seed_values:
                    continue
                if self.in_scope(norm) is None:
                    denied.setdefault(DENY_CT_OUT_OF_SCOPE, set()).add(norm)
                    continue
                if new_depth > self.config.limits.max_depth:
                    denied.setdefault(DENY_DEPTH, set()).add(norm)
                    continue
                batch.reach(subject, "certificate_mentions_hostname", "hostname", norm, [ev.id], seed_id,
                            new_depth, [("dns", norm)])
        for reason, names in denied.items():
            batch.deny(reason, len(names))

    def _dns(self, batch: _Batch, res: SourceResult, ev: Evidence, seed_id: str, depth: int,
             from_aid: str | None) -> None:
        subject = from_aid or asset_id("hostname", ev.query)
        new_depth = depth + 1
        for addr in res.data.get("addresses") or []:
            try:
                ip = str(ipaddress.IPv4Address(str(addr)))
            except ValueError:
                continue
            if non_global_address(ip):
                batch.deny(DENY_NON_GLOBAL)  # CONTEXT: stays in the DNS evidence, never sent to a source
                continue
            if new_depth > self.config.limits.max_depth:
                batch.deny(DENY_DEPTH)
                continue
            batch.reach(subject, "hostname_resolves_to_ip", "ip", ip, [ev.id], seed_id, new_depth,
                        [("rdap", ip), ("internetdb", ip)])

    def _internetdb_hostnames(self, batch: _Batch, res: SourceResult, ev: Evidence, seed_id: str, depth: int,
                              ip_aid: str | None) -> None:
        if ip_aid is None:
            return
        for raw in res.data.get("hostnames") or []:
            norm = _normalize_name(str(raw))
            if norm is None or norm.startswith("*") or norm in self.domain_seed_values:
                continue
            if self.in_scope(norm) is None:
                continue  # CONTEXT: stays on the ip's evidence only
            # Enrichment never increases depth and never creates tasks.
            batch.reach(ip_aid, "ip_reports_hostname", "hostname", norm, [ev.id], seed_id, depth, [])


def _rdap_covered(ip: str, cache: list[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in net for net in cache)


def _cidrs_of(ev_data: dict[str, Any], query: str | None = None) -> list[ipaddress.IPv4Network]:
    """Cacheable cidrs of an RDAP answer: IPv4, no larger than a /8, and containing the queried address."""
    try:
        addr = ipaddress.IPv4Address(query) if query is not None else None
    except ValueError:
        return []
    out = []
    for c in ev_data.get("cidrs") or []:
        try:
            net = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network) or net.prefixlen < 8:
            continue
        if addr is None or addr not in net:
            continue
        out.append(net)
    return out


def non_global_address(ip: str) -> bool:
    """Special-purpose IPv4 space (scope.SPECIAL_PURPOSE_NETWORKS), documentation ranges excepted."""
    from .scope import DOCUMENTATION_NETWORKS, SPECIAL_PURPOSE_NETWORKS
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return any(addr in block for block, _name in SPECIAL_PURPOSE_NETWORKS if block not in DOCUMENTATION_NETWORKS)


# --------------------------------------------------------------------------- main loop

def execute(store: Store, run_id: str, connectors: dict[SourceName, Connector], stop: threading.Event, *,
            workers: int = 8, batch_size: int = 64) -> str:
    """Seed initial tasks if the run has none yet, then process pending tasks in batches until none remain
    ("done"), `stop` is set ("stopped", after committing the current batch), or a limit ends the run
    ("done", with truncation recorded). Resumable: calling again continues from the persisted queue."""
    run = store.run(run_id)
    if run is None:
        raise ValueError(f"unknown run {run_id}")
    config = _load_config(run)
    if not store.has_tasks(run_id):
        _seed(store, run_id, config)
    handler = _Handler(config)
    limits = config.limits
    started = _clock()
    prior_elapsed = float(run.get("elapsed_seconds") or 0.0)
    queries_used = int(run.get("query_count") or 0)
    last_mark = started

    def account_time() -> None:
        nonlocal last_mark
        now = _clock()
        store.add_elapsed(run_id, max(0.0, now - last_mark))
        last_mark = now

    def end_with_truncation(limit: str, detail: str) -> str:
        account_time()
        skipped = store.skip_pending_tasks(run_id)
        store.commit_batch(run_id, done_task_ids=[], evidence=[], assets=[], relationships=[], new_tasks=[],
                           coverage=[], queries=0, source_failures={}, out_of_scope={},
                           truncations=[Truncation(limit=limit, omitted=skipped, detail=detail)])
        return "done"

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        while True:
            if stop.is_set():
                account_time()
                return "stopped"
            if prior_elapsed + (_clock() - started) >= limits.max_seconds:
                if store.pending_tasks(run_id, 1):
                    return end_with_truncation(
                        "max_seconds", f"max_seconds ({limits.max_seconds}) reached; remaining tasks skipped")
                account_time()
                return "done"
            tasks = sorted(store.pending_tasks(run_id, batch_size), key=lambda t: t["id"])
            if not tasks:
                account_time()
                return "done"

            # Walk tasks in order. Non-rdap calls run concurrently; rdap tasks are decided one at a time, after every
            # earlier rdap call of this batch has answered, so a later address inside an earlier answer's network
            # reuses it (deterministic, and the same however the batch's calls complete).
            rdap_cache: list[ipaddress.IPv4Network] = []
            for ev in store.rdap_cache(run_id):
                rdap_cache.extend(_cidrs_of(ev.data, ev.query))
            budget = limits.max_queries - queries_used
            plan: list[dict[str, Any]] = []
            futures: dict[int, Any] = {}
            pending_rdap: list[dict[str, Any]] = []
            results: dict[int, SourceResult | None] = {}
            over_budget = False

            def drain_rdap() -> None:
                for rt in pending_rdap:
                    res = _safe_result(futures[rt["id"]], rt)
                    results[rt["id"]] = res
                    if res.status == "ok":
                        rdap_cache.extend(_cidrs_of(res.data, rt["query"]))
                pending_rdap.clear()

            for t in tasks:
                if t["source"] == "rdap":
                    drain_rdap()
                    if _rdap_covered(t["query"], rdap_cache):
                        plan.append(t)
                        results[t["id"]] = None
                        continue
                if t["source"] not in connectors:
                    raise ValueError(f"no connector for source {t['source']!r}")
                if budget <= 0:
                    over_budget = True
                    break
                budget -= 1
                plan.append(t)
                futures[t["id"]] = pool.submit(connectors[t["source"]].fetch, t["query"])
                if t["source"] == "rdap":
                    pending_rdap.append(t)
            drain_rdap()
            for t in plan:
                if t["id"] not in results:
                    results[t["id"]] = _safe_result(futures[t["id"]], t)

            batch = _Batch(store, run_id, config)
            batch.queries = len(futures)
            for t in plan:  # apply strictly in task id order
                handler.apply(batch, t, results[t["id"]])
            batch.commit([t["id"] for t in plan])
            queries_used += len(futures)
            account_time()

            if stop.is_set():
                return "stopped"
            if over_budget:
                return end_with_truncation(
                    "max_queries", f"max_queries ({limits.max_queries}) reached; remaining tasks skipped")


def _safe_result(future: Any, task: dict[str, Any]) -> SourceResult:
    """Connectors never raise by contract; a raise is still recorded as a source error, not a crashed run."""
    try:
        return future.result()
    except Exception as exc:  # noqa: BLE001
        return SourceResult(source=task["source"], query=task["query"], status="error", retrieved_at=_now_iso(),
                            source_url="", error=f"{type(exc).__name__}: {exc}"[:200])
