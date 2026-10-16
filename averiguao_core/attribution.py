"""Attribution, reconciliation and findings (docs/RULES.md sections 3-6). Pure functions. Owner: graph/attribution agent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import (Assertion, Evidence, Finding, InventoryMatch, InventorySnapshot, Relationship, RunConfig)
from .store import Store


@dataclass
class Assessment:
    assertions: list[Assertion]
    matches: list[InventoryMatch]
    findings: list[Finding]


def assess(config: RunConfig, assets: list[dict[str, Any]], relationships: list[Relationship],
           evidence: list[Evidence], snapshot: InventorySnapshot, *, completed_at: str,
           truncated: bool, source_errors: dict[str, list[str]] | None = None) -> Assessment:
    """assets: Store.assets() rows. source_errors: asset_id -> evidence ids of failed source calls about it."""
    raise NotImplementedError


def assess_run(store: Store, run_id: str) -> None:
    """Load everything for the run, use the current inventory snapshot (creating the empty baseline snapshot and
    the run flag 'empty_inventory' if none exists), assess, and save_assessment."""
    raise NotImplementedError
