"""Hostile-data world for the security probes: every source-controlled free-text field carries markup,
formula and Markdown payloads. Built from the demo world so the pipeline paths are realistic. No network."""

from __future__ import annotations

import http.client
import tempfile
import threading
from typing import Any

from averiguao_core import server as server_mod
from averiguao_core.connectors.fake import DEMO_CONFIG, demo_world
from tests.fixtures.pipeline import run_pipeline

XSS = '<img src=x onerror="window.__pwned=1">'
REMOTE_IMG = '![t](http://attacker.invalid/px.png)'
LINK = '[click](javascript:alert(1))'
HTML_MD = '<script>window.__pwned=2</script>'
FORMULA_DDE = "=cmd|' /C calc'!A0"
# A value with no comma, quote or newline so csv.writer does not quote it; Excel in ';'-list-separator locales
# (de, fr, es, it, nl, pt-BR ...) splits it at ';' and evaluates the second piece.
SEMI_FORMULA = "CVE-2024-0001;=1+1+cmd|'/C calc'!A0"

HOSTILE_ORG = f"{XSS} {REMOTE_IMG}"[:100]
HOSTILE_RDAP = {
    "handle": f"H{XSS}", "network_name": f"{LINK} | broken | table", "cidrs": ["203.0.113.0/26"],
    "org_names": [f"{XSS}{REMOTE_IMG}", "+SUM(1,2)"], "entity_handles": [HTML_MD], "country": "US",
    "registration_date": None, "last_changed": None,
}
HOSTILE_RDAP_SEMI = {
    "handle": "NET-SEMI", "network_name": "SEMI-NET", "cidrs": ["203.0.113.64/27"],
    "org_names": ["Vendor;=1+1+cmd|'/C calc'!A0"], "entity_handles": [], "country": "US",
    "registration_date": None, "last_changed": None,
}
HOSTILE_IDB = {
    "ports": [22, 443], "hostnames": [],
    "cpes": [XSS, REMOTE_IMG], "tags": [HTML_MD, LINK],
    "vulns": [SEMI_FORMULA, "@SUM(1)", FORMULA_DDE, f"CVE-1 {XSS}\n# heading\n| a | b |"],
}

HOSTILE_CONFIG = {
    **DEMO_CONFIG,
    "label": f"=HYPERLINK(1) {XSS} {REMOTE_IMG} {HTML_MD}"[:200],
    "approval_ref": f"-2+3 {XSS} {LINK}"[:200],
    "org_names": [HOSTILE_ORG, "Example Corp"],
}
HOSTILE_INVENTORY = (
    "value,label\n"
    f"198.51.100.0/30,\"{XSS} {REMOTE_IMG}\"\n"
    "www.example.com,=1+1\n"
)


def hostile_world():
    return demo_world(overrides={
        "rdap": {"203.0.113.50": HOSTILE_RDAP, "203.0.113.80": HOSTILE_RDAP_SEMI},
        "internetdb": {"198.51.100.9": HOSTILE_IDB, "203.0.113.50": HOSTILE_IDB},
    })


def build_hostile_run(tmpdir: str):
    return run_pipeline(hostile_world(), HOSTILE_CONFIG, HOSTILE_INVENTORY, tmpdir=tmpdir)


class NullRunner:
    def submit(self, run_id): pass
    def pause(self, run_id): raise ValueError("no")
    def resume(self, run_id): raise ValueError("no")
    def reassess(self, run_id): raise ValueError("no")


TOKEN = "h" * 43  # fixed access token for the hostile fixture server


def start_server(store, *, demo: bool = True):
    httpd = server_mod.make_server(store, NullRunner(), port=0, token=TOKEN, demo=demo,
                                   demo_config=dict(HOSTILE_CONFIG))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def raw_request(port: int, method: str, path: str, headers: dict[str, str] | None = None,
                body: bytes | None = None, *, host: str | None = "default"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    if host == "default":
        conn.putheader("Host", f"127.0.0.1:{port}")
    elif host is not None:
        conn.putheader("Host", host)
    merged = {"Cookie": f"averiguao_{port}={TOKEN}", **(headers or {})}
    for key, value in merged.items():
        if value is not None:  # None drops the default access-token cookie
            conn.putheader(key, value)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response, payload


class HostileRun:
    """Lazily built shared fixture (one pipeline run per test process)."""
    _cache: dict[str, Any] = {}

    @classmethod
    def get(cls):
        if not cls._cache:
            tmp = tempfile.TemporaryDirectory(prefix="averiguao-sec-")
            store, run_id = build_hostile_run(tmp.name)
            cls._cache.update(tmp=tmp, store=store, run_id=run_id)
        return cls._cache["store"], cls._cache["run_id"]
