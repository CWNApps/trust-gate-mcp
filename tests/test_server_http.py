"""test_server_http.py -- the HTTP entrypoint: its helpers and the whole app end to end."""
from __future__ import annotations

import importlib
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture()
def http(monkeypatch):
    pytest.importorskip("starlette")
    # server_http.py is deployed as flat modules next to server.py, so import it that way, from the
    # package directory of the code under test (which is not always ROOT).
    import trust_gate_mcp
    monkeypatch.syspath_prepend(str(pathlib.Path(trust_gate_mcp.__file__).resolve().parent))
    return importlib.import_module("server_http")


def test_only_three_attribution_labels_are_built_in(http):
    assert http.channel_labels({}) == {"direct", "github", "smithery"}


def test_further_labels_come_from_the_environment_and_are_validated(http):
    got = http.channel_labels({"TRUST_GATE_CHANNELS": " Foo-Bar, baz ,,BAD LABEL,-x,y" + "z" * 40 + ",ok9"})
    assert got == {"direct", "github", "smithery", "foo-bar", "baz", "ok9"}


def _call(name, **arguments):
    import json
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}})


def test_the_middleware_stack_is_wired_end_to_end(http, monkeypatch):
    """Auth, rate limit, CORS and the browser explainer are actually in the app main() serves."""
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient
    token = "t" * 32
    monkeypatch.setenv("TRUST_GATE_BEARER_TOKEN", token)
    monkeypatch.setenv("TRUST_GATE_ALLOWED_ORIGINS", "https://ok.example")
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "1")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "50")
    app = http.build_app()
    json_headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    with TestClient(app, client=("9.9.9.9", 50000)) as client:
        sign = _call("gate_decision", action="read_file", resource="docs", context={})
        assert client.post("/mcp", content=sign, headers=json_headers).status_code == 401            # no token
        wrong = {**json_headers, "authorization": "Bearer nope"}
        assert client.post("/mcp", content=sign, headers=wrong).status_code == 401                    # wrong token
        non_ascii = {**json_headers, "authorization": "Bearer té"}
        assert client.post("/mcp", content=sign, headers={k: v.encode("utf-8") for k, v in non_ascii.items()}).status_code == 401
        good = {**json_headers, "authorization": f"Bearer {token}"}
        assert client.post("/mcp", content=sign, headers=good).status_code != 429                     # first signing call
        assert client.post("/mcp", content=sign, headers=good).status_code == 429                     # second: over the budget
        # CORS allowlist, not a wildcard, once bearer auth is on
        pre = client.options("/mcp", headers={"origin": "https://ok.example", "access-control-request-method": "POST"})
        assert pre.headers.get("access-control-allow-origin") == "https://ok.example"
        pre = client.options("/mcp", headers={"origin": "https://evil.example", "access-control-request-method": "POST"})
        assert pre.headers.get("access-control-allow-origin") != "https://evil.example"


def test_a_browser_visit_to_the_endpoint_gets_the_explainer_without_spending_a_token(http, monkeypatch):
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "1")
    app = http.build_app()
    with TestClient(app, client=("8.8.8.8", 50000)) as client:
        for _ in range(3):
            page = client.get("/mcp", headers={"accept": "text/html"})
            assert page.status_code == 200 and "MCP endpoint" in page.text
        assert "Verify a Trust Gate receipt yourself" not in page.text
        card = client.get("/.well-known/mcp/server-card.json")
        assert card.status_code == 200 and card.json()["version"]


def test_the_counter_records_only_known_labels(http, monkeypatch, capsys):
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("TRUST_GATE_CHANNELS", "example-channel")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "100")
    app = http.build_app()
    with TestClient(app, client=("7.7.7.7", 50000)) as client:
        assert client.get("/x?via=example-channel&kind=api").json()["via"] == "example-channel"
        assert client.get("/x?via=github&kind=card").json()["kind"] == "card"
        assert client.get("/x?via=made-up&kind=bogus").json() == {
            "ok": True, "via": "unknown", "kind": "page", "ua_family": client.get("/x").json()["ua_family"]}
        assert client.get("/x").json()["via"] == "direct"


def _mcp_message(response):
    """The JSON-RPC message in a response that is plain JSON or a single server-sent event."""
    import json
    text = response.text.strip()
    if "data:" in text:
        text = next(line[5:].strip() for line in text.splitlines() if line.startswith("data:"))
    return json.loads(text)


def test_real_mcp_requests_reach_the_application_with_their_bodies(http, monkeypatch):
    """The limiter reads every POST body to classify and cap it; the application must still get it.
    (A limiter that swallowed the body made every MCP call fail with a parse error.)"""
    pytest.importorskip("httpx")
    import json
    from starlette.testclient import TestClient
    monkeypatch.delenv("TRUST_GATE_BEARER_TOKEN", raising=False)
    app = http.build_app()
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}}}
    with TestClient(app, client=("7.7.7.7", 50000)) as client:
        first = client.post("/mcp", content=json.dumps(init), headers=headers)
        assert first.status_code == 200 and _mcp_message(first)["result"]["serverInfo"]["name"]
        listing = client.post("/mcp", content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                              headers=headers)
        names = {tool["name"] for tool in _mcp_message(listing)["result"]["tools"]}
        assert listing.status_code == 200 and {"gate_decision", "verify_receipt", "check_egress"} <= names
        allow = client.post("/mcp", content=_call("gate_decision", action="read_file", resource="docs", context={}),
                            headers=headers)
        assert allow.status_code == 200 and '"ALLOW"' in json.dumps(_mcp_message(allow)["result"])
        deny = client.post("/mcp", content=_call("gate_decision", action="delete_database", resource="prod", context={}),
                           headers=headers)
        assert deny.status_code == 200 and '"DENY"' in json.dumps(_mcp_message(deny)["result"])
