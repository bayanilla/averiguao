"""Source connectors. Each implements contracts.Connector and never raises for source failures."""

from __future__ import annotations

from ..contracts import Connector, SourceName


def live_connectors(rates: dict[str, float] | None = None) -> dict[SourceName, Connector]:
    """Real connectors with their default (or overridden) request rates per second."""
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
