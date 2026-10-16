"""Scope guard: parse and validate seeds, run configuration and inventory; decide what discovery may record.

Owner: scope agent. See docs/RULES.md sections 1 and 2.
"""

from __future__ import annotations

from typing import Any

from .contracts import Decision, InventorySnapshot, RunConfig, Seed


class ScopeError(ValueError):
    """Raised for invalid input. The message is shown to the user and names the line or field."""


def parse_seeds(text: str, approval_ref: str, scope_version: str = "1",
                max_prefix_addresses: int = 4096) -> tuple[Seed, ...]:
    """Parse one seed per line (blank lines and '#' comments ignored). Raises ScopeError."""
    raise NotImplementedError


def parse_run_config(body: dict[str, Any]) -> RunConfig:
    """Build a RunConfig from the API/CLI JSON shape:
    {"seeds": "multi-line text", "approval_ref": str, "scope_version": str?, "org_names": [str] | "comma,separated",
     "label": str?, "limits": {Limits fields}?, "match_rules": {"prefix_containment": bool, "domain_hierarchy": bool}?}
    Raises ScopeError."""
    raise NotImplementedError


def run_config_from_dict(data: dict[str, Any]) -> RunConfig:
    """Inverse of RunConfig.to_dict() (used when loading a stored run). No re-validation of limits needed."""
    raise NotImplementedError


def parse_inventory(csv_text: str, label: str = "", as_of: str | None = None) -> InventorySnapshot:
    """Parse inventory CSV into a new snapshot (RULES.md 1, Inventory). Raises ScopeError."""
    raise NotImplementedError


def normalize_hostname(name: str) -> str | None:
    """Lowercase, strip trailing dot, IDNA-encode. Return None if not a valid hostname. '*.x' is returned unchanged
    (callers decide what to do with wildcards)."""
    raise NotImplementedError


class ScopePolicy:
    """Answers scope questions for one run. Pure; no I/O."""

    def __init__(self, config: RunConfig):
        raise NotImplementedError

    def in_scope_domain(self, name: str) -> str | None:
        """Return the domain seed value that `name` equals or falls under, else None."""
        raise NotImplementedError

    def decide(self, predicate: str, object_value: str, depth: int) -> Decision:
        """Decision for recording `object_value` reached via `predicate` at `depth` (RULES.md 2 table).
        predicate is one of: "certificate_mentions_hostname", "hostname_resolves_to_ip", "ip_reports_hostname",
        "prefix_contains_ip", "rdap_enrichment", "cname_target"."""
        raise NotImplementedError

    def prefix_addresses(self, seed: Seed) -> list[str]:
        """Every address of a prefix seed, in order."""
        raise NotImplementedError
