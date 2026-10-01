"""test_rate_limit_classification.py -- signing tools must land in the signing budget.

0.2.1 chose a bucket by looking for the words "mint_" or "verify_" anywhere in the raw request
text. gate_decision, check_egress and run_exit_drill sign receipts but were counted in the larger
default budget, a "verify_" string placed inside a tool's arguments moved a signing call into the
verify budget, and a JSON escape (m\\u0069nt_action_receipt) hid the word altogether. The limiter
now reads the tool name from the parsed JSON-RPC request.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("starlette")
from trust_gate_mcp.rate_limit import RateLimitMiddleware  # noqa: E402


@pytest.fixture()
def mw():
    async def app(scope, receive, send):  # never called; the classifier is pure
        return None
    return RateLimitMiddleware(app)


def _which(mw, body):
    buckets, cap = mw._bucket_for(body)
    if buckets is mw._mint_buckets:
        return "mint"
    if buckets is mw._verify_buckets:
        return "verify"
    assert buckets is mw._default_buckets
    return "default"


def _call(name, **arguments):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}})


@pytest.mark.parametrize("tool", ["mint_receipt_for_record_change", "mint_action_receipt", "gate_decision",
                                  "check_egress", "run_exit_drill"])
def test_every_signing_tool_uses_the_signing_budget(mw, tool):
    assert _which(mw, _call(tool)) == "mint"


def test_verify_uses_the_verify_budget(mw):
    assert _which(mw, _call("verify_receipt", receipt={})) == "verify"


@pytest.mark.parametrize("tool", ["audit_my_agent_inventory"])
def test_read_only_tools_use_the_default_budget(mw, tool):
    assert _which(mw, _call(tool)) == "default"


def test_handshake_and_listing_use_the_default_budget(mw):
    assert _which(mw, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})) == "default"
    assert _which(mw, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})) == "default"


def test_a_verify_word_inside_the_arguments_does_not_move_a_signing_call(mw):
    body = _call("gate_decision", action="read_file", resource="docs", context={"note": "verify_receipt verify: mint"})
    assert _which(mw, body) == "mint"
    body = _call("mint_action_receipt", agent_id="a", operation="verify_x", target="t")
    assert _which(mw, body) == "mint"


def test_a_json_escape_cannot_hide_the_tool_name(mw):
    body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"m\\u0069nt_action_receipt","arguments":{}}}'
    assert _which(mw, body) == "mint"


def test_a_batch_is_charged_at_its_most_expensive_call(mw):
    batch = json.dumps([json.loads(_call("verify_receipt")), json.loads(_call("gate_decision")),
                        json.loads(_call("audit_my_agent_inventory"))])
    assert _which(mw, batch) == "mint"


def test_a_body_that_cannot_be_parsed_is_charged_to_the_signing_budget(mw):
    for body in ("not json mint_action_receipt", "not json verify_receipt", "not json at all", "[" * 100000, "{", "\x00\x01"):
        assert _which(mw, body) == "mint", body
    assert _which(mw, "") == "default"            # nothing to classify


@pytest.mark.parametrize("codec", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"])
def test_every_encoding_the_transport_can_read_is_classified_the_same_way(mw, codec):
    """The application parses the raw bytes (a byte-order mark, UTF-16 and UTF-32 included), so the limiter must too."""
    body = _call("gate_decision", action="read_file", resource="docs", context={"note": "verify_receipt"}).encode(codec)
    assert json.loads(body)["params"]["name"] == "gate_decision"       # what the application will read
    assert _which(mw, body) == "mint"
    verify = _call("verify_receipt", receipt={}).encode(codec)
    assert _which(mw, verify) == "verify"


# ==== the middleware end to end (dispatch), not only the classifier ==============================
def _app(monkeypatch, mint=2, verify=3, default=5):
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", str(mint))
    monkeypatch.setenv("RATE_LIMIT_VERIFY_PER_MIN", str(verify))
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", str(default))
    pytest.importorskip("httpx")
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def ok(_request):
        return JSONResponse({"ok": True})

    return Starlette(routes=[Route("/mcp", ok, methods=["POST", "GET"])],
                     middleware=[Middleware(RateLimitMiddleware)])


def _client_at(app, ip="1.1.1.1"):
    from starlette.testclient import TestClient
    return TestClient(app, client=(ip, 50000))


def _post(client, body, headers=None):
    return client.post("/mcp", content=body, headers={"content-type": "application/json", **(headers or {})})


def test_the_signing_budget_is_enforced_per_client_and_verify_has_its_own(monkeypatch):
    app = _app(monkeypatch)
    one, other = _client_at(app, "1.1.1.1"), _client_at(app, "2.2.2.2")
    sign = _call("gate_decision", action="read_file")
    assert [_post(one, sign).status_code for _ in range(3)] == [200, 200, 429]
    assert _post(one, _call("verify_receipt")).status_code == 200      # a separate bucket
    assert _post(other, sign).status_code == 200                       # another client
    limited = _post(one, sign)
    assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
    assert limited.json()["error"] == "rate_limited"


def test_a_client_cannot_buy_a_new_budget_by_changing_its_forwarded_for_header(monkeypatch):
    app = _app(monkeypatch)
    client = _client_at(app)
    sign = _call("gate_decision", action="read_file")
    codes = [_post(client, sign, {"x-forwarded-for": f"10.0.0.{i}, 9.9.9.9"}).status_code for i in range(4)]
    assert codes == [200, 200, 429, 429]


def test_padding_a_signing_call_past_the_parse_cap_still_costs_a_signing_token(monkeypatch):
    app = _app(monkeypatch)
    client = _client_at(app)
    padded = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "gate_decision", "arguments": {"action": "x" * (70 * 1024)}}})
    assert RateLimitMiddleware.MAX_BODY_BYTES < len(padded) < RateLimitMiddleware.MAX_REQUEST_BYTES
    assert [_post(client, padded).status_code for _ in range(3)] == [200, 200, 429]


def test_a_utf16_body_is_charged_by_the_tool_it_names(monkeypatch):
    app = _app(monkeypatch)
    client = _client_at(app)
    utf16 = _call("mint_action_receipt", agent_id="a").encode("utf-16")
    assert [_post(client, utf16).status_code for _ in range(3)] == [200, 200, 429]
    assert _post(client, _call("verify_receipt").encode("utf-16")).status_code == 200      # its own budget
    assert _post(client, b"\xff\xfe not json at all \xff").status_code == 429          # cannot be parsed: signing budget


def test_a_request_over_the_size_cap_is_refused_before_it_is_buffered(monkeypatch):
    app = _app(monkeypatch)
    client = _client_at(app)
    big = b"x" * (RateLimitMiddleware.MAX_REQUEST_BYTES + 1)
    assert _post(client, big).status_code == 413

    def chunks():                                     # no Content-Length: the streamed total is capped too
        for _ in range(9):
            yield b"y" * (RateLimitMiddleware.MAX_REQUEST_BYTES // 8)
    assert client.post("/mcp", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    assert _post(client, _call("verify_receipt")).status_code == 200


def test_production_limits_are_the_documented_ones():
    assert RateLimitMiddleware.MAX_BODY_BYTES == 64 * 1024
    assert RateLimitMiddleware.MAX_REQUEST_BYTES == 1024 * 1024
    assert RateLimitMiddleware.MAX_BUCKETS_PER_CLASS == 4096


def test_the_oldest_client_is_the_one_evicted_when_the_bucket_store_is_full():
    mw = RateLimitMiddleware(app=None)
    mw.MAX_BUCKETS_PER_CLASS = 3
    store = {}
    for ip in ("a", "b", "c", "d"):
        mw._get_or_create(store, ip, 5)
    assert list(store) == ["b", "c", "d"]


def test_a_token_bucket_never_holds_more_than_its_capacity_however_long_it_idles():
    from trust_gate_mcp.rate_limit import TokenBucket
    bucket = TokenBucket(capacity=2, window_seconds=60.0)
    bucket.last -= 10_000            # idle for hours
    assert [bucket.take() for _ in range(4)] == [True, True, False, False]


def test_a_non_positive_or_malformed_budget_falls_back_to_the_default(monkeypatch):
    from trust_gate_mcp.rate_limit import _budget
    for raw in ("0", "-5", "abc", ""):
        monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", raw)
        assert _budget("RATE_LIMIT_MINT_PER_MIN", 60) == 60, raw
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "7")
    assert _budget("RATE_LIMIT_MINT_PER_MIN", 60) == 7


def _echo_app(monkeypatch):
    """An application behind the limiter that reports how many body bytes reached it."""
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "1000")
    monkeypatch.setenv("RATE_LIMIT_VERIFY_PER_MIN", "1000")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "1000")
    pytest.importorskip("httpx")
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def echo(request):
        body = await request.body()
        return JSONResponse({"length": len(body), "same": body == request.headers.get("x-expect", "").encode("latin-1")})

    return Starlette(routes=[Route("/mcp", echo, methods=["POST", "PUT", "PATCH", "GET"])],
                     middleware=[Middleware(RateLimitMiddleware)])


def test_the_application_receives_the_exact_body_the_limiter_read(monkeypatch):
    client = _client_at(_echo_app(monkeypatch))
    small = _call("gate_decision", action="read_file")
    got = client.post("/mcp", content=small, headers={"content-type": "application/json", "x-expect": small}).json()
    assert got == {"length": len(small), "same": True}
    padded = "x" * (RateLimitMiddleware.MAX_BODY_BYTES + 10)          # over the parse cap, under the size cap
    got = client.post("/mcp", content=padded, headers={"content-type": "text/plain", "x-expect": padded}).json()
    assert got == {"length": len(padded), "same": True}
    utf16 = "héllo".encode("utf-16")                                    # not UTF-8: still delivered whole
    assert client.post("/mcp", content=utf16, headers={"content-type": "text/plain"}).json()["length"] == len(utf16)
    for method in ("put", "patch"):
        assert getattr(client, method)("/mcp", content=small).json()["length"] == len(small)
    assert client.get("/mcp").json()["length"] == 0                     # a GET is not read at all


def test_a_chunked_upload_is_delivered_whole(monkeypatch):
    client = _client_at(_echo_app(monkeypatch))
    parts = [b"a" * 1000, b"b" * 1000, b"c" * 1000]
    assert client.post("/mcp", content=iter(parts), headers={"content-type": "text/plain"}).json()["length"] == 3000
