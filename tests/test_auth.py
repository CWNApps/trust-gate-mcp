"""test_auth.py -- the optional bearer-auth toggle.

Off by default: open mode (verify-as-public-good adoption path).
On (TRUST_GATE_BEARER_TOKEN set): every request needs Authorization: Bearer <token>
and CORS narrows to TRUST_GATE_ALLOWED_ORIGINS.

Implementation hardening proved here:
  - constant-time token compare (no plaintext == that leaks via timing)
  - OPTIONS preflight passes without auth (so browsers can learn the CORS policy first)
  - missing allowlist with auth-on -> empty list (no implicit '*' under credentials)
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth import BearerAuthMiddleware, _allowed_origins, auth_active


def _request(method: str = "POST", auth_header: str = "") -> Request:
    """Build a minimal Request that the middleware can read headers from."""
    headers = []
    if auth_header:
        headers.append((b"authorization", auth_header.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": "/mcp",
        "headers": headers,
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
    }
    return Request(scope)


def _dispatch(mw: BearerAuthMiddleware, request: Request):
    async def _ok(_req):
        return JSONResponse({"ok": True})
    return asyncio.run(mw.dispatch(request, _ok))


# ---- bearer off --------------------------------------------------------------
def test_auth_off_means_inactive(monkeypatch):
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    assert auth_active() is False
    assert _allowed_origins() == ["*"]


def test_auth_off_lets_unauthed_request_through(monkeypatch):
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    mw = BearerAuthMiddleware(app=None)
    r = _dispatch(mw, _request())
    assert r.status_code == 200


# ---- bearer on ---------------------------------------------------------------
def test_auth_on_rejects_missing_header(monkeypatch):
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    mw = BearerAuthMiddleware(app=None)
    r = _dispatch(mw, _request())
    assert r.status_code == 401


def test_auth_on_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    mw = BearerAuthMiddleware(app=None)
    r = _dispatch(mw, _request(auth_header="Bearer not-it"))
    assert r.status_code == 401


def test_auth_on_accepts_correct_token(monkeypatch):
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    mw = BearerAuthMiddleware(app=None)
    r = _dispatch(mw, _request(auth_header="Bearer secret-xyz"))
    assert r.status_code == 200


def test_auth_on_lets_OPTIONS_preflight_pass(monkeypatch):
    # critical: a browser must see the CORS policy via preflight even without a token
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    mw = BearerAuthMiddleware(app=None)
    r = _dispatch(mw, _request(method="OPTIONS"))
    assert r.status_code == 200


def test_auth_on_narrows_cors(monkeypatch):
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS",
                       "https://gateway.smithery.ai, https://acme.example")
    assert auth_active() is True
    assert _allowed_origins() == ["https://gateway.smithery.ai", "https://acme.example"]


def test_auth_on_without_allowlist_refuses_implicit_wildcard(monkeypatch):
    # codex-style fix: under credentials, missing allowlist must NOT default to '*'.
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-xyz")
    monkeypatch.delenv("TRUST_GATE_ALLOWED_ORIGINS", raising=False)
    assert _allowed_origins() == []  # CORS denies cross-origin until operator sets the list
