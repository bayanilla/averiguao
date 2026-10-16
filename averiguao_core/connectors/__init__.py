"""Source connectors. Each implements contracts.Connector and never raises for source failures."""

from __future__ import annotations

import threading

from ..contracts import Connector, SourceName

_LIVE: dict[tuple, dict[SourceName, Connector]] = {}
_LIVE_LOCK = threading.Lock()


def live_connectors(rates: dict[str, float] | None = None) -> dict[SourceName, Connector]:
    """Real connectors with their default (or overridden) request rates per second.

    Built once per process for a given set of rates, so rate spacing and any cooldown a source imposed
    survive pauses, resumes and later runs."""
    key = tuple(sorted((rates or {}).items()))
    with _LIVE_LOCK:
        if key not in _LIVE:
            _LIVE[key] = _build_live(rates)
        return _LIVE[key]


def _build_live(rates: dict[str, float] | None) -> dict[SourceName, Connector]:
    from .ct import CTConnector
    from .dns import DNSConnector
    from .internetdb import InternetDBConnector
    from .rdap import RDAPConnector
    rates = rates or {}
    return {
        "ct": CTConnector(rate=rates.get("ct", CTConnector.DEFAULT_RATE)),
        "dns": DNSConnector(rate=rates.get("dns", DNSConnector.DEFAULT_RATE)),
        "rdap": RDAPConnector(rate=rates.get("rdap", RDAPConnector.DEFAULT_RATE)),
        "internetdb": InternetDBConnector(rate=rates.get("internetdb", InternetDBConnector.DEFAULT_RATE)),
    }
