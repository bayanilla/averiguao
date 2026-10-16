# Stage 1 rules (normative)

This file is the implemented behaviour of the Stage 1 pipeline. `averiguao_core/contracts.py` defines the records; this file defines what fills them. Where it is stricter or narrower than `ARCHITECTURE.md`, this file wins and the difference is listed at the end.

## 1. Inputs

### Seeds

One seed per line. Accepted forms:

| Input | Seed type | Normalization |
| --- | --- | --- |
| `example.com`, `Example.COM.` | `domain` | lowercase, IDNA-encoded, trailing dot removed. Must have at least two labels, each a valid DNS label. A public suffix alone (`com`, `co.uk`) is rejected via a small built-in list of common suffixes. Wildcards are rejected. |
| `198.51.100.7` | `ip` | canonical IPv4 |
| `198.51.100.0/24` | `prefix` | canonical network. Host bits set (`198.51.100.7/24`) is **rejected**, not silently masked. `/32` becomes an `ip` seed. |

Rejected for every IP seed: IPv6, any network that **overlaps** a non-global range (check every special-purpose block in `ipaddress`, not `is_global` on the network), prefixes larger than `limits.max_prefix_addresses` (and never above `HARD_MAX_PREFIX_ADDRESSES` = 65,536, a /16). Errors name the line and the reason.

Every run requires a non-empty `approval_ref` (max 200 chars) and at least one seed (max 50 seeds). `org_names` is optional (max 20, each 2–100 chars); without it, ownership of IPs can never be `supported` and the UI says so. Limits are validated: all positive integers, `max_depth` 1–3, `max_seconds` ≤ 86,400, `max_queries` ≤ 200,000.

### Inventory

CSV `value,label` (header row optional: first cell `value`, `ip`, `ip_or_cidr`, `cidr`, `network`, `asset`). `value` is an IPv4 address (`ip`), an IPv4 CIDR (`cidr`, host bits rejected), a hostname (`hostname`, exact name), or `*.example.com` (`domain_tree`, covers `example.com` and all names under it). Inventory may contain any public or private address (it describes the organization, not a query). Max 10,000 entries; duplicate values keep the first. An optional `as_of` is passed separately from the CSV. Saving creates a new **snapshot**; snapshots are never edited or deleted, and the newest is "current".

A run captures the current snapshot id when it **completes**; a run cannot complete without a snapshot. If none exists, an empty snapshot labelled "empty baseline" is created automatically and the run gets the flag `empty_inventory` on its metadata. Re-reconciling a completed run against a newer snapshot recomputes assertions/matches/findings only (no new queries).

## 2. Discovery (engine)

The engine is a persisted work queue of **tasks** `(source, query, seed_id, depth, from_asset_id)`. Tasks are processed in batches; each batch's results and the new tasks it produces commit in one transaction, so a crash or pause loses at most the in-flight batch, which is retried on resume. **Cancel** stops a run at the next batch boundary (a queued or paused run at once), marks its pending tasks skipped, records a `cancelled` truncation with the number skipped, and assesses what was collected. A cancelled run cannot be resumed but can be reassessed and exported.

Initial tasks:

- `domain` seed `d`: create asset `domain:d` (relationship `seed_is`, depth 0, evidence `ev:seed:<n>`). Tasks: `ct d` and `dns d`, both depth 0 from `domain:d`.
- `ip` seed `a`: asset `ip:a` via `seed_is`, depth 0. Enrichment tasks: `rdap a`, `internetdb a`.
- `prefix` seed `p`: `rdap <network address>` once, and `internetdb <ip>` for every address in `p` (depth 1, from the seed). An address becomes an `ip` asset (`prefix_contains_ip`) only if InternetDB returns `ok`; `no_record` and `error` results are written to **coverage** so every checked address is listed.

Result handling (all names normalized; a name is **in scope** when it equals or is a subdomain of a `domain` seed value):

| Source result | Produces | Scope decision |
| --- | --- | --- |
| `ct` names | `certificate_mentions_hostname` domain → hostname, evidence = that certificate | Wildcard `*.x` is reduced to `x`. In scope and new depth ≤ max_depth → **EXPAND** (task `dns name`). Out of scope (other tenants on a shared certificate, look-alike domains) → **DENY**. If the reduced name equals the seed domain, nothing new. |
| `dns` addresses | `hostname_resolves_to_ip` (from `domain:` or `hostname:` asset) → ip | Depth ≤ max_depth → **RECORD** + enrichment tasks `rdap`, `internetdb` for the ip. Depth > max_depth → **DENY** (`depth_limit`). |
| `dns` addresses in special-purpose space (private, loopback, link-local, CGNAT, multicast, reserved, broadcast, `0.0.0.0/8`; documentation ranges excepted so the synthetic world works) | nothing; the addresses stay in the DNS evidence | **CONTEXT** (`non_global_address`). Never recorded as candidates and never sent to any source. The hostname gets flag `non_global_address` (public DNS exposing internal addressing is itself worth review). |
| `dns` cnames | no relationship; the chain stays in the DNS evidence `data.cnames` | **CONTEXT** (used by attribution) |
| `internetdb` hostnames on an ip | `ip_reports_hostname` ip → hostname | In scope → **RECORD** (candidate, no DNS task). Out of scope → **CONTEXT** (other tenants of shared hosting stay on the ip's evidence only). |
| `rdap` | enrichment evidence on the ip | **CONTEXT**. The RDAP result is cached per run by its `cidrs`: an ip inside an already-fetched RDAP network reuses that evidence without a query, including within the same batch (the first answer is reused by later tasks in task order). A cidr is only cached if it contains the address that was queried and is no larger than a /8; otherwise the answer is used for that address alone. |

Enrichment never increases depth and never creates further tasks. No source is ever asked about an address or name the engine did not reach through these rules: no neighbour addresses, no covering or adjacent prefixes, no names from out-of-scope certificates.

Deduplication: one task per `(source, query)` per run, whichever seed reached it first (an address reached from a domain seed and a prefix seed is queried once). One asset per id. A relationship is identified by `(subject, predicate, object, seed)`; repeated observations append evidence ids. The asset's **path** is the first relationship chain that reached it (BFS order, so shortest).

Limits: when recording a new hostname or ip would exceed `max_hostnames`/`max_addresses`, it is not recorded, its tasks are not created, and a `Truncation` is added/incremented. `max_queries` and `max_seconds` stop the run with remaining tasks marked `skipped` and a `Truncation`. A truncated run still **completes** (status `complete`, `truncated` non-empty) so its findings are usable; the UI and every report show the truncation prominently. Source errors are counted per source and listed as `source_failures` in reports.

Out-of-scope decisions (`DENY`) are counted per reason in run metadata `out_of_scope` (`{"ct_name_outside_approved_domains": 12, "depth_limit": 3}`; names that fail normalization count as `invalid_name`). A hostname recorded from InternetDB takes the depth of its ip and is never resolved, so the boundary is visible.

## 3. Attribution (per candidate asset)

Candidates are every `hostname` and `ip` asset plus `ip` seeds. `domain` seed assets are not candidates. Four assertions are always produced per candidate, ids `as:<asset_id>:<dimension>`.

Organization match: an RDAP result matches the organization when any `org_names` entry equals (case-insensitive, whitespace-collapsed) or is a whole-word substring of any of `org_names`, `network_name`, `entity_handles` or `handle`.

**hostname**

| Dimension | Rule |
| --- | --- |
| ownership | In scope (always true for recorded hostnames) → `supported`, value = the matching domain seed, evidence = that seed's `ev:seed:<n>`, rationale names the approval_ref. |
| operational_control | If the latest DNS evidence has a CNAME chain whose **final** target is outside the approved domains → `contradicted`, value = registrable-ish base of that target (last two labels, or three for known two-level suffixes), evidence = the DNS evidence. Otherwise `unresolved`. |
| hosting | If it resolves: value = the RDAP org (first of org_names, else network_name) of its addresses when all agree → `supported`; disagreeing providers → `unresolved` with flag `conflict`. No resolution → `unresolved`. |
| service_association | `supported` (in-scope name observed in CT, DNS or InternetDB), evidence = those observations. |

**ip**

| Dimension | Rule |
| --- | --- |
| ownership | RDAP ok and organization match → `supported`, value = matched org name. RDAP ok and no match → `contradicted`, value = RDAP org/network name. No RDAP / error / no org_names configured → `unresolved`. |
| operational_control | Every hostname path reaching this ip passed through an external CNAME → `contradicted` (value = that external operator). Some do and some don't → `unresolved` + flag `conflict`. Otherwise `unresolved`. (Address registration alone never supports control.) |
| hosting | RDAP ok → `supported`, value = RDAP org (first org_names entry, else network_name). Else `unresolved`. |
| service_association | Reached from an in-scope hostname/domain via DNS, or InternetDB reports an in-scope hostname → `supported`. Else `unresolved`. |

Conflicting evidence is never discarded: supporting and contradicting evidence ids are both listed.

**Role**: `third_party` if operational_control is `contradicted`; else `first_party` if ownership or operational_control is `supported`; else `unresolved`.

## 4. Reconciliation

For each candidate, against the run's snapshot, first rule that applies:

1. `exact`: ip equals an `ip` entry (or a `/32` cidr); hostname equals a `hostname` entry → `matched`.
2. `prefix_containment`: ip inside a `cidr` entry (most specific wins) → `matched` if `match_rules.prefix_containment`, else `indeterminate`.
3. `domain_hierarchy`: hostname equal to or under a `domain_tree` entry (most specific wins) → `matched` if `match_rules.domain_hierarchy`, else `indeterminate`.
4. otherwise `unmatched` (rule `none`, entry null).

**Queue**: `matched` → `known`. `indeterminate` → `unexplained` + flag `inventory_match_indeterminate`. `unmatched` → `new` if role `first_party`, `third_party` if role `third_party`, else `unexplained`.

## 5. Flags

`conflict`, `inventory_match_indeterminate`, `stale_evidence` (the asset has at least one `ok` observation from ct/dns/internetdb, and every such observation has a `valid_to` before the run's completion time; observations without `valid_to`, such as DNS answers, count as current; seed evidence and no_record/error results are ignored), `no_resolution` (a DNS query for the hostname was made and returned no_record; hostnames recorded only from InternetDB are never resolved and do not get this flag), `source_error` (a source call about this asset failed), `potential_vulns` (InternetDB listed vulns), `non_global_address` (hostname resolves to special-purpose space), `truncated_run` (the run hit a limit).

DNS evidence has `valid_from`/`valid_to` = None (the TTL stays in `data`). RDAP and InternetDB evidence also have no validity period.

## 6. Rank

`rank = queue_weight + 0.1 × distinct_sources + (0.2 if potential_vulns) + (0.1 if open ports reported) − (0.3 if stale_evidence)`, where `distinct_sources` counts the distinct sources among the asset's `ok` evidence (excluding `scope`); queue weights `new` 3, `unexplained` 2, `third_party` 1, `known` 0. Findings are listed rank-descending, then by value.

## 7. Reports

All three formats contain the same finding ids, queues and assessments.

- **JSON** (`averiguao-<run8>.json`): `{"run": {id, status, label, created_at, finished_at, config, approval refs, inventory_snapshot {id, as_of, label, entry_count}, truncated, out_of_scope, source_failures, query_count, coverage_summary}, "seeds", "assets", "evidence", "relationships", "assertions", "inventory_matches", "findings", "coverage"}`. Source of truth.
- **CSV** (`averiguao-<run8>.csv`): one row per finding, columns `finding_id, asset_id, asset_type, value, queue, role, inventory_match, match_rule, inventory_entry, ownership, ownership_value, operational_control, operational_control_value, hosting, hosting_value, service_association, seed_id, seed_path, evidence_ids, first_observed, last_observed, flags, ports, vulns, rank`. Lists are `;`-joined. **Every** cell that begins with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with `'`.
- **Markdown** (`averiguao-<run8>.md`): every finding id appears (an "All findings" table at the end lists id, value, queue, role for every finding). Run header (seeds, approval refs, snapshot, limits), a warning block for truncation and source failures, counts by queue, top 20 `new` and `unexplained` by rank, third-party dependencies, conflicts, stale evidence, then one concise evidence path per listed finding (`seed:1 example.com → [CT ev:…] staging.example.com → [DNS ev:…] 198.51.100.9`). Escape Markdown control characters in all source-derived text.

## 8. Differences from ARCHITECTURE.md

- Seeds: `domain`, `ip`, `prefix`. ASN seeds and BGP are not implemented.
- DNS is live resolution through a public DNS-over-HTTPS resolver, not a passive DNS database. It never contacts the investigated hosts, but it is current-state, not historical.
- Sources: crt.sh (CT), Cloudflare DoH (DNS), rdap.org (RDAP, following redirects to the five RIRs), Shodan InternetDB.
- Review state is always `unreviewed`; analyst review workflow is not implemented.
