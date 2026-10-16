"""Reports built from hostile source data: CSV formula injection, Markdown injection, JSON integrity.

Source-controlled text (RDAP org/network names, InternetDB cpes/tags/vulns) and analyst-supplied text
(run label, approval ref, inventory labels) carry formula, HTML and Markdown payloads (see _hostile.py)."""

from __future__ import annotations

import csv
import io
import json
import re
import unittest

from averiguao_core import reports
from tests.security._hostile import HostileRun, SEMI_FORMULA

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv_rows():
    store, run_id = HostileRun.get()
    text = b"".join(reports.csv_report(store, run_id)).decode("utf-8")
    return text, list(csv.reader(io.StringIO(text)))


class CsvInjection(unittest.TestCase):
    def test_no_cell_starts_with_a_formula_character(self):
        """Guard: every CSV cell (all 25 columns) that would start with = + - @ tab CR is prefixed with '."""
        _, rows = _csv_rows()
        self.assertGreater(len(rows), 5)
        for row in rows:
            for column, cell in zip(rows[0], row):
                self.assertFalse(cell.startswith(FORMULA_START), f"{column}: {cell!r}")

    def test_hostile_values_reached_the_csv(self):
        """Guard for the probe itself: the hostile RDAP and InternetDB strings are present in the CSV."""
        text, _ = _csv_rows()
        self.assertIn("calc", text)
        self.assertIn("Vendor;", text)

    def test_semicolon_joined_list_items_cannot_start_a_formula(self):
        """ISSUE (CSV formula injection via ';'): list cells (vulns, ports, flags, seed_path, evidence_ids) are
        ';'-joined and only the first character of the whole cell is checked, and source-controlled scalars
        (RDAP org names in ownership_value/hosting_value, InternetDB vulns) may themselves contain ';'. A cell
        without ',', '"' or a newline is written unquoted, so Excel in locales whose list separator is ';'
        (de, fr, es, it, nl, pt-BR ...) splits it there and evaluates the piece after the ';' — e.g. the
        InternetDB vuln "CVE-2024-0001;=1+1+cmd|'/C calc'!A0" or the RDAP org "Vendor;=1+1+cmd|...".
        EXPECTED: no ';'-separated segment of any cell starts with a formula character (neutralise each list
        item and any source text containing ';', or always quote such cells / replace ';' in source text)."""
        _, rows = _csv_rows()
        offenders = []
        for row in rows[1:]:
            for column, cell in zip(rows[0], row):
                for segment in cell.split(";")[1:]:
                    if segment.startswith(FORMULA_START):
                        offenders.append((row[0], column, cell[:80]))
        self.assertEqual(offenders, [], "formula after ';' in CSV cells")
        self.assertTrue(SEMI_FORMULA)


class MarkdownInjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store, run_id = HostileRun.get()
        cls.text = b"".join(reports.markdown_report(store, run_id)).decode("utf-8")

    def test_no_raw_html_links_or_images(self):
        """Guard: no unescaped '<', '![', '](' or '[' from source text survives into the Markdown."""
        unescaped = re.compile(r"(?<!\\)(<|!\[|\]\(|\[)")
        bad = [line for line in self.text.splitlines() if unescaped.search(line)]
        self.assertEqual(bad, [])
        self.assertIn("attacker", self.text)  # the payload was present and escaped

    def test_tables_keep_their_column_count(self):
        """Guard: source text with '|' or newlines cannot add columns or rows to a Markdown table."""
        lines = self.text.splitlines()
        width = None
        for line in lines:
            if line.startswith("|"):
                cells = len(re.findall(r"(?<!\\)\|", line))
                if width is None:
                    width = cells
                self.assertEqual(cells, width, line[:200])
            else:
                width = None

    def test_no_injected_block_starts(self):
        """Guard: hostile text never starts a heading, list item, quote or HTML block on its own line."""
        for line in self.text.splitlines():
            if line.startswith(("#", ">", "- ", "|")) or not line.strip() or line[0].isalnum():
                continue
            self.fail(f"unexpected block start: {line[:120]!r}")
        for line in self.text.splitlines():
            if line.startswith("#"):
                self.assertRegex(line, r"^#{1,2} [A-Z]")


class JsonIntegrity(unittest.TestCase):
    def test_json_report_is_valid_and_lossless(self):
        """Guard: the JSON report parses and keeps hostile strings verbatim (it is the source of truth)."""
        store, run_id = HostileRun.get()
        data = json.loads(b"".join(reports.json_report(store, run_id)))
        dumped = json.dumps(data)
        self.assertIn("onerror", dumped)
        self.assertIn(SEMI_FORMULA, json.dumps(data["evidence"]))


if __name__ == "__main__":
    unittest.main()
