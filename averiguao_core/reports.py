"""JSON, CSV and Markdown reports (docs/RULES.md section 7). Owner: reports/UI agent. Streams; never builds
the whole report in memory when it can be avoided."""

from __future__ import annotations

from typing import Iterator

from .store import Store


def json_report(store: Store, run_id: str) -> Iterator[bytes]: raise NotImplementedError
def csv_report(store: Store, run_id: str) -> Iterator[bytes]: raise NotImplementedError
def markdown_report(store: Store, run_id: str) -> Iterator[bytes]: raise NotImplementedError
def safe_cell(value: object) -> str: raise NotImplementedError
