"""Shared helpers for the adversarial probes (FakeConnector worlds; no network)."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from averiguao_core import engine, scope
from averiguao_core.connectors.fake import FakeConnector
from averiguao_core.store import Store

CLOCK = "2026-10-01T00:00:00+00:00"


def cert(cid, names):
    return {"id": cid, "names": names, "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00", "issuer": "CA"}


def a(name, addresses, cnames=()):
    return {"name": name, "cnames": list(cnames), "addresses": list(addresses), "ttl": 300}


def idb(ports=(), hostnames=(), vulns=()):
    return {"ports": list(ports), "hostnames": list(hostnames), "cpes": [], "tags": [], "vulns": list(vulns)}


def rdap(name, cidrs, org="Corp"):
    return {"handle": f"NET-{name}", "network_name": name, "cidrs": list(cidrs), "org_names": [org],
            "entity_handles": [], "country": "US", "registration_date": None, "last_changed": None}


def world(ct=None, dns=None, rdap=None, internetdb=None, rdap_fallback=None):
    return {
        "ct": FakeConnector("ct", ct or {}, clock=CLOCK),
        "dns": FakeConnector("dns", dns or {}, clock=CLOCK),
        "rdap": FakeConnector("rdap", rdap or {}, clock=CLOCK, fallback=rdap_fallback),
        "internetdb": FakeConnector("internetdb", internetdb or {}, clock=CLOCK),
    }


def queried(w):
    return {(name, q) for name, c in w.items() for q in c.queries()}


class WorldCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="averiguao-adv-")
        self.addCleanup(self._tmp.cleanup)
        self._n = 0

    def run_world(self, seeds, w, *, limits=None, workers=4, batch_size=64, org_names=("Corp",)):
        self._n += 1
        store = Store(Path(self._tmp.name) / f"db{self._n}.sqlite3")
        body = {"seeds": seeds, "approval_ref": "TICKET-ADV", "org_names": list(org_names),
                "limits": limits or {}}
        config = scope.parse_run_config(body, allow_documentation_ranges=True)
        run_id = store.create_run(config)
        status = engine.execute(store, run_id, w, threading.Event(), workers=workers, batch_size=batch_size)
        self.assertEqual(status, "done")
        return store, run_id

    @staticmethod
    def asset_ids(store, run_id):
        return {row["asset"].id if hasattr(row["asset"], "id") else row["asset"]["id"]
                for row in store.assets(run_id)}
