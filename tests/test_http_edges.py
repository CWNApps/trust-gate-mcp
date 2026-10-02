"""test_http_edges.py -- HTTP behaviour: bearer matching, credentialed CORS, the size cap being enforced while
the body streams in, which methods are limited, and the server card."""
from __future__ import annotations

import asyncio
import importlib
import json
import pathlib

import pytest

import trust_gate_mcp

JSON_HEADERS = {"content-type": "application/json", "accept": "application/json, text/event-stream"}


@pytest.fixture()
def http(monkeypatch):
    pytest.importorskip("starlette")
    pytest.importorskip("httpx")
    monkeypatch.syspath_prepend(str(pathlib.Path(trust_gate_mcp.__file__).resolve().parent))
    return importlib.import_module("server_http")


def _call(name, **arguments):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}})


# ---- bearer tokens are matched whole ----------------------------------------------------------------------
@pytest.mark.parametrize("presented, status", [
    ("secret-token-value", 200), ("secret-token-valueX", 401), ("secret-token-valu", 401), ("Xsecret-token-value", 401),
    ("SECRET-TOKEN-VALUE", 401), ("", 401), ("secret-token-value extra", 401),
])
def test_only_the_exact_token_is_accepted(http, monkeypatch, presented, status):
    from starlette.testclient import TestClient
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-token-value")
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS", "https://ok.example")
    with TestClient(http.build_app(), client=("5.5.5.5", 40000)) as client:
        headers = {**JSON_HEADERS, "authorization": f"Bearer {presented}"}
        listing = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert client.post("/mcp", content=listing, headers=headers).status_code == status


def test_a_missing_or_non_bearer_authorization_header_is_refused(http, monkeypatch):
    from starlette.testclient import TestClient
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-token-value")
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS", "https://ok.example")
    with TestClient(http.build_app(), client=("5.5.5.5", 40000)) as client:
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert client.post("/mcp", content=body, headers=JSON_HEADERS).status_code == 401
        basic = {**JSON_HEADERS, "authorization": "Basic secret-token-value"}
        assert client.post("/mcp", content=body, headers=basic).status_code == 401


# ---- CORS: credentials only with an allowlist ---------------------------------------------------------------
def test_without_bearer_auth_cors_never_allows_credentials(http, monkeypatch):
    from starlette.testclient import TestClient
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    with TestClient(http.build_app(), client=("6.6.6.6", 40000)) as client:
        pre = client.options("/mcp", headers={"origin": "https://evil.example",
                                              "access-control-request-method": "POST"})
        assert pre.headers.get("access-control-allow-origin") == "*"
        assert "access-control-allow-credentials" not in {k.lower() for k in pre.headers}


def test_with_bearer_auth_only_listed_origins_get_credentials(http, monkeypatch):
    from starlette.testclient import TestClient
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", "secret-token-value")
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS", "https://ok.example")
    with TestClient(http.build_app(), client=("6.6.6.6", 40000)) as client:
        good = client.options("/mcp", headers={"origin": "https://ok.example", "access-control-request-method": "POST"})
        assert good.headers.get("access-control-allow-origin") == "https://ok.example"
        assert good.headers.get("access-control-allow-credentials") == "true"
        bad = client.options("/mcp", headers={"origin": "https://evil.example", "access-control-request-method": "POST"})
        assert bad.headers.get("access-control-allow-origin") is None


# ---- the browser explainer must not capture a real MCP client ----------------------------------------------
def _explainer_decisions(http, monkeypatch, accept, method="GET", path="/mcp"):
    """Drive the explainer middleware directly: did it answer, or hand the request on? (A real GET that accepts an
    event stream opens a stream that never ends, so it cannot be driven through a test client.)"""
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    app = http.build_app()
    cls = next(m.cls for m in app.user_middleware if m.cls.__name__ == "MCPBrowserExplainerMiddleware")
    passed, sent = [], []

    async def downstream(scope, receive, send):
        passed.append(True)

    async def send(message):
        sent.append(message)

    headers = [(b"accept", accept.encode("latin-1"))] if accept is not None else []
    scope = {"type": "http", "method": method, "path": path, "headers": headers}
    asyncio.run(cls(downstream)(scope, None, send))
    return bool(passed), sent


def test_the_explainer_answers_only_a_browser_that_does_not_also_accept_an_event_stream(http, monkeypatch):
    answered = _explainer_decisions(http, monkeypatch, "text/html,application/xhtml+xml")
    assert answered[0] is False and answered[1][0]["status"] == 200
    assert b"MCP endpoint" in answered[1][1]["body"]
    for accept in ("text/html, text/event-stream", "text/event-stream", "application/json", None):
        passed, sent = _explainer_decisions(http, monkeypatch, accept)
        assert passed is True and sent == [], accept
    assert _explainer_decisions(http, monkeypatch, "text/html", method="POST")[0] is True
    assert _explainer_decisions(http, monkeypatch, "text/html", path="/other")[0] is True


# ---- the served card names the running version ---------------------------------------------------------------
def test_the_server_card_names_the_running_version_and_tools(http, monkeypatch):
    from starlette.testclient import TestClient
    with TestClient(http.build_app(), client=("8.8.4.4", 40000)) as client:
        card = client.get("/.well-known/mcp/server-card.json").json()
    assert card["version"] == trust_gate_mcp.__version__
    assert len(card["tools"]) == 7 and "gate_decision" in {t["name"] for t in card["tools"]}
    assert str(len(card["tools"])) in card["description"]


# ---- the limiter --------------------------------------------------------------------------------------------
def _app(monkeypatch, mint=2, default=50):
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", str(mint))
    monkeypatch.setenv("RATE_LIMIT_VERIFY_PER_MIN", "50")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", str(default))
    pytest.importorskip("httpx")
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from trust_gate_mcp.rate_limit import RateLimitMiddleware

    async def ok(_request):
        return JSONResponse({"ok": True})

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    return Starlette(routes=[Route("/mcp", ok, methods=methods)], middleware=[Middleware(RateLimitMiddleware)])


@pytest.mark.parametrize("method", ["post", "put", "patch"])
def test_a_signing_call_costs_a_signing_token_whichever_method_carries_it(monkeypatch, method):
    from starlette.testclient import TestClient
    client = TestClient(_app(monkeypatch), client=("3.3.3.3", 40000))
    sign = _call("gate_decision", action="read_file")
    codes = [getattr(client, method)("/mcp", content=sign, headers=JSON_HEADERS).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_the_size_cap_stops_reading_the_body_as_soon_as_it_is_exceeded(monkeypatch):
    """The 413 is sent while the upload is still arriving, not after the whole body was buffered."""
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "10")
    reads, sent = [], []

    async def app(scope, receive, send):
        raise AssertionError("an oversized request must never reach the application")

    limiter = RateLimitMiddleware(app)
    chunk = b"x" * (RateLimitMiddleware.MAX_REQUEST_BYTES // 2 + 1)

    async def receive():
        reads.append(1)
        if len(reads) > 2:
            raise AssertionError("the limiter kept reading after the cap was exceeded")
        return {"type": "http.request", "body": chunk, "more_body": True}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": [], "query_string": b"",
             "client": ("9.9.9.9", 1), "scheme": "http", "server": ("t", 80), "http_version": "1.1"}
    asyncio.run(limiter(scope, receive, send))
    assert len(reads) == 2
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 413


def test_a_client_that_disconnects_mid_upload_gets_nothing_and_reaches_nothing(monkeypatch):
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    sent = []

    async def app(scope, receive, send):
        raise AssertionError("a half-received request must never reach the application")

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": [], "query_string": b"",
             "client": ("9.9.9.9", 1), "scheme": "http", "server": ("t", 80), "http_version": "1.1"}
    asyncio.run(RateLimitMiddleware(app)(scope, receive, send))
    assert sent == []


def test_non_http_scopes_pass_straight_through(monkeypatch):
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    asyncio.run(RateLimitMiddleware(app)({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


# ---- client identity: what the documented deployment setting does --------------------------------------------
def test_the_forwarded_for_header_is_honoured_only_from_the_proxies_you_name(monkeypatch):
    """Documents the deployment setting: uvicorn resolves X-Forwarded-For before the limiter runs. With
    TRUST_GATE_FORWARDED_ALLOW_IPS unset ("*"), any client can pick its own identity; naming your proxy's
    address closes that for connections that do not come from it."""
    pytest.importorskip("uvicorn")
    from starlette.testclient import TestClient
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
    sign = _call("gate_decision", action="read_file")

    def codes(trusted, peer):
        wrapped = ProxyHeadersMiddleware(_app(monkeypatch), trusted_hosts=trusted)
        client = TestClient(wrapped, client=(peer, 40000))
        return [client.post("/mcp", content=sign, headers={**JSON_HEADERS, "x-forwarded-for": f"10.1.1.{i}"}).status_code
                for i in range(4)]

    assert codes("*", "203.0.113.5") == [200, 200, 200, 200]      # documented weakness of the default
    assert codes("198.51.100.1", "203.0.113.5") == [200, 200, 429, 429]


@pytest.mark.parametrize("codec", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le"])
def test_an_encoded_signing_call_costs_a_signing_token_and_an_encoded_verify_does_not(monkeypatch, codec):
    """Through the middleware itself: whatever encoding the transport can read, the call is charged to the
    tool it names, not to the default budget."""
    from starlette.testclient import TestClient
    client = TestClient(_app(monkeypatch), client=("3.3.3.4", 40000))
    sign = _call("gate_decision", action="read_file", context={"note": "verify_receipt"}).encode(codec)
    headers = {"content-type": "application/json"}
    assert [client.post("/mcp", content=sign, headers=headers).status_code for _ in range(3)] == [200, 200, 429]
    verify = _call("verify_receipt", receipt={}).encode(codec)
    assert client.post("/mcp", content=verify, headers=headers).status_code == 200      # its own budget
