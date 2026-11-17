"""test_artex_actions.py -- what an autonomous pentest agent (ARTEX workers) sends must never come back ALLOW.

docs/artex.md tells ARTEX operators to call gate_decision before consequential actions. These tests pin the
promise that guide makes: every recon, scanning, exploitation, credential and data-exfiltration action an
ARTEX worker is likely to name is escalated or denied, never allowed, whatever target it names; and the
HTTP endpoint ARTEX connects to answers POST /mcp directly, with no redirect a client could follow to
another host while carrying its headers.

The gate itself is unchanged. If one of these starts returning ALLOW, the vocabulary grew a word it should not
have: fix the vocabulary, not this list.
"""
from __future__ import annotations

import importlib
import pathlib

import pytest

from trust_gate_mcp import server as srv

PENTEST_ACTIONS = [
    "scan host", "scan ports", "port scan", "nmap scan", "run nmap", "run nuclei", "run sqlmap",
    "run ffuf", "run dalfox", "run katana", "run httpx", "enumerate subdomains", "discover endpoints",
    "fuzz endpoint", "fuzz parameters", "crawl site", "probe service", "fingerprint service",
    "exploit sql injection", "exploit xss", "exploit vulnerability", "execute payload", "upload webshell",
    "run exploit", "brute force login", "spray passwords", "crack hashes", "use credential",
    "login with credentials", "replay token", "dump database", "exfiltrate data", "download backup",
    "pivot to host", "move laterally", "escalate privileges", "bypass waf", "bypass edr",
    "disable antivirus", "create mcp server", "create custom tool", "send request", "post request",
]

TARGETS = [
    "10.0.0.5", "192.168.1.0/24", "example.com", "https://app.example.com/login",
    "https://api.example.com/v1/users?id=1", "/api/users", "target", "docs",
]


@pytest.mark.parametrize("action", PENTEST_ACTIONS)
@pytest.mark.parametrize("resource", TARGETS)
def test_pentest_action_is_never_allowed(action, resource):
    assessment = srv._gate_assessment(action, resource)
    assert assessment["verdict"] in ("ESCALATE", "DENY"), (action, resource, assessment)


@pytest.mark.parametrize("action", ["exploit sql injection", "brute force login", "dump database", "scan host"])
def test_pentest_commit_never_grants_a_permit(action):
    pv = srv.tool_gate_decision(action, "https://app.example.com/login", {}, phase="PREVIEW")
    assert "error" not in pv, pv
    cm = srv.tool_gate_decision(action, "https://app.example.com/login", {}, phase="COMMIT",
                                preview_id=pv["preview_id"])
    assert cm.get("permit") != "GRANTED", cm
    if srv._oao_receipt is not None:
        assert cm["receipt"]["decision"] in ("ESCALATE", "DENY"), cm["receipt"]["decision"]


def test_mcp_endpoint_answers_without_a_redirect(monkeypatch):
    """ARTEX's MCP client follows redirects and copies custom headers to the new location; the
    endpoint it is pointed at must answer in place."""
    pytest.importorskip("starlette")
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient
    import trust_gate_mcp
    monkeypatch.syspath_prepend(str(pathlib.Path(trust_gate_mcp.__file__).resolve().parent))
    http = importlib.import_module("server_http")
    token = "a" * 32
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", token)
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS", "https://ok.example")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "100")
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "100")
    body = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26",'
            '"capabilities":{},"clientInfo":{"name":"artex","version":"0.6.0"}}}')
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
               "authorization": f"Bearer {token}"}
    with TestClient(http.build_app(), client=("9.9.9.9", 50000), follow_redirects=False) as client:
        r = client.post("/mcp", content=body, headers=headers)
        assert not (300 <= r.status_code < 400), (r.status_code, r.headers.get("location"))
        assert r.status_code == 200, r.status_code
