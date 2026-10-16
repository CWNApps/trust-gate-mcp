"""test_api_ops.py -- the nine read-only API views, on a mocked HTTP layer (no network).

Every test replaces the HTTP client with one on httpx.MockTransport, so nothing here can reach a
real service. Fail-closed cases come first: a missing setting, a 404, a server error and a wrong
shape must each be a typed UNAVAILABLE and must never carry data.
"""
from __future__ import annotations

import json

import pytest

httpx = pytest.importorskip("httpx")

from trust_gate_mcp import api_ops  # noqa: E402

SECRET = "tgk-test-secret-value-1234567890"
TENANT = "tenant-acme"
BASE = "https://api.example.test"
ALL_OPS = sorted(api_ops.OPERATIONS)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("TRUST_GATE_API_URL", BASE)
    monkeypatch.setenv("TRUST_GATE_API_KEY", SECRET)
    monkeypatch.setenv("TRUST_GATE_TENANT_ID", TENANT)


@pytest.fixture
def transport(monkeypatch):
    """Install a mock transport. Returns a list that records each request the client made."""
    class Seen(list):
        def set(self, fn):
            box["handler"] = fn

    seen = Seen()
    box = {"handler": lambda request: httpx.Response(200, json={"ok": True})}

    def factory(timeout):
        def handler(request):
            seen.append(request)
            return box["handler"](request)
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout, follow_redirects=False)

    monkeypatch.setattr(api_ops, "_client_factory", factory)
    return seen


def _assert_closed(result, status="UNAVAILABLE"):
    assert result["status"] == status
    assert result["data"] is None
    assert result["read_only"] is True
    assert "not a compliance finding" in result["notice"]


# ---- fail closed: nothing is invented ------------------------------------------------------------------------
@pytest.mark.parametrize("missing", ["TRUST_GATE_API_URL", "TRUST_GATE_API_KEY", "TRUST_GATE_TENANT_ID"])
def test_a_missing_setting_is_unavailable_and_makes_no_call(configured, transport, monkeypatch, missing):
    monkeypatch.delenv(missing)
    r = api_ops.call("inspect_oversight_case", {"records": [1]})
    _assert_closed(r)
    assert r["reason"] == "not_configured"
    assert transport == []


def test_nothing_set_at_all_is_unavailable(transport, monkeypatch):
    for name in ("TRUST_GATE_API_URL", "TRUST_GATE_API_KEY", "TRUST_GATE_TENANT_ID"):
        monkeypatch.delenv(name, raising=False)
    _assert_closed(api_ops.call("export_acceptance_pack", {"cases": []}))
    assert transport == []


@pytest.mark.parametrize("op", ALL_OPS)
def test_a_404_is_unavailable_for_every_operation(configured, transport, op):
    transport.set(lambda request: httpx.Response(404, json={"detail": "Not Found"}))
    r = api_ops.call(op, {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "surface_not_available"


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_rate_limit_and_server_errors_are_unavailable(configured, transport, status):
    transport.set(lambda request: httpx.Response(status, json={"code": "whatever", "report": {"a": 1}}))
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "service_unavailable"


def test_a_transport_error_is_unavailable_and_leaks_nothing(configured, monkeypatch):
    def factory(timeout):
        def handler(request):
            raise httpx.ConnectError("boom " + str(request.url) + SECRET)
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)
    monkeypatch.setattr(api_ops, "_client_factory", factory)
    r = api_ops.call("replay_decision", {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "transport_error"
    assert SECRET not in json.dumps(r) and "example.test" not in json.dumps(r)


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"text"', b"null"])
def test_an_answer_of_the_wrong_shape_is_unavailable(configured, transport, body):
    transport.set(lambda request: httpx.Response(200, content=body))
    _assert_closed(api_ops.call("get_decision_evidence", {"x": 1}))


def test_an_answer_missing_the_expected_field_is_unavailable_not_empty(configured, transport):
    transport.set(lambda request: httpx.Response(200, json={"status": "OK"}))
    for op in ("inspect_oversight_case", "get_intervention_evidence"):
        r = api_ops.call(op, {"x": 1})
        _assert_closed(r)
        assert r["reason"] == "response_wrong_shape"


def test_an_oversized_answer_is_unavailable(configured, transport):
    transport.set(lambda request: httpx.Response(200, json={"pad": "x" * (api_ops.MAX_RESPONSE_BYTES + 10)}))
    r = api_ops.call("propose_requalification", {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "response_too_large"


def test_a_redirect_is_not_followed(configured, transport):
    transport.set(lambda request: httpx.Response(302, headers={"location": "https://elsewhere.example.test/"}))
    r = api_ops.call("get_receipt_evidence", {"x": 1})
    _assert_closed(r, "REFUSED")
    assert len(transport) == 1


# ---- refusals ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("status,code", [(400, "cross_tenant_record"), (403, "tenant_mismatch"), (401, "unauthenticated"),
                                         (413, "payload_too_large"), (422, "INPUT_REFUSED")])
def test_an_api_refusal_is_refused_with_its_short_code_only(configured, transport, status, code):
    transport.set(lambda request: httpx.Response(status, json={"status": "DENIED", "code": code, "trace": "secret stack text"}))
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    _assert_closed(r, "REFUSED")
    assert r["code"] == code
    assert "secret stack text" not in json.dumps(r)


def test_a_nested_error_code_is_read_and_free_text_is_never_passed_on(configured, transport):
    transport.set(lambda request: httpx.Response(422, json={"detail": {"code": "BAD_INPUT"}}))
    assert api_ops.call("replay_decision", {"x": 1})["code"] == "BAD_INPUT"
    transport.set(lambda request: httpx.Response(422, json={"code": "has spaces and <script>"}))
    assert "code" not in api_ops.call("replay_decision", {"x": 1})


@pytest.mark.parametrize("bad", [None, [], "text", 5, {}])
def test_the_request_must_be_a_non_empty_object(configured, transport, bad):
    _assert_closed(api_ops.call("inspect_oversight_case", bad), "REFUSED")
    assert transport == []


def test_an_unknown_operation_is_refused(configured, transport):
    _assert_closed(api_ops.call("delete_everything", {"x": 1}), "REFUSED")
    assert transport == []


def test_a_request_that_cannot_be_serialised_or_is_too_large_is_refused(configured, transport):
    _assert_closed(api_ops.call("replay_decision", {"x": float("nan")}), "REFUSED")
    _assert_closed(api_ops.call("replay_decision", {"x": object()}), "REFUSED")
    _assert_closed(api_ops.call("replay_decision", {"x": "y" * (api_ops.MAX_REQUEST_BYTES + 1)}), "REFUSED")
    assert transport == []


# ---- tenant comes from configuration, never from an argument -------------------------------------------------
@pytest.mark.parametrize("key", ["tenant_id", "tenant", "tenantId"])
@pytest.mark.parametrize("op", ALL_OPS)
def test_a_model_supplied_tenant_is_refused_before_any_call(configured, transport, op, key):
    r = api_ops.call(op, {key: "someone-else", "x": 1})
    _assert_closed(r, "REFUSED")
    assert r["reason"] == "tenant_is_configuration_not_an_argument"
    assert transport == []


@pytest.mark.parametrize("op", ALL_OPS)
def test_the_configured_tenant_is_the_only_one_sent(configured, transport, op):
    api_ops.call(op, {"records": [{"id": "r1"}]})
    req = transport[0]
    assert req.headers["x-cwn-tenant-id"] == TENANT
    body = json.loads(req.content)
    if api_ops.OPERATIONS[op]["body_tenant"]:
        assert body["tenant_id"] == TENANT
    else:
        assert not any(k in body for k in ("tenant_id", "tenant", "tenantId"))
    assert body["records"] == [{"id": "r1"}]


# ---- the credential and the route -----------------------------------------------------------------------------
@pytest.mark.parametrize("op", ALL_OPS)
def test_the_credential_goes_in_the_bearer_header_and_nowhere_else(configured, transport, op):
    r = api_ops.call(op, {"x": 1})
    req = transport[0]
    assert req.method == "POST"
    assert req.headers["authorization"] == "Bearer " + SECRET
    assert SECRET not in str(req.url) and SECRET.encode() not in req.content
    assert str(req.url) == BASE + api_ops.OPERATIONS[op]["path"]
    assert SECRET not in json.dumps(r)


def test_no_tool_logs_the_credential(configured, transport, caplog):
    caplog.set_level("DEBUG")
    transport.set(lambda request: httpx.Response(500))
    api_ops.call("inspect_oversight_case", {"x": 1})
    transport.set(lambda request: httpx.Response(200, json={"report": {}}))
    api_ops.call("inspect_oversight_case", {"x": 1})
    assert SECRET not in caplog.text


@pytest.mark.parametrize("url", ["ftp://api.example.test", "http://api.example.test", "https://user:pw@api.example.test",
                                 "https://api.example.test/?key=1", "not a url", "https://"])
def test_an_unsafe_url_setting_is_unavailable_and_makes_no_call(configured, transport, monkeypatch, url):
    monkeypatch.setenv("TRUST_GATE_API_URL", url)
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "url_setting_invalid"
    assert transport == []


def test_plain_http_is_allowed_only_for_localhost(configured, transport, monkeypatch):
    monkeypatch.setenv("TRUST_GATE_API_URL", "http://127.0.0.1:8080/")
    api_ops.call("inspect_oversight_case", {"x": 1})
    assert str(transport[0].url) == "http://127.0.0.1:8080" + api_ops.OPERATIONS["inspect_oversight_case"]["path"]


@pytest.mark.parametrize("tenant", ["a b", "../x", "x" * 65, "-lead", "t;drop"])
def test_an_invalid_tenant_setting_is_unavailable(configured, transport, monkeypatch, tenant):
    monkeypatch.setenv("TRUST_GATE_TENANT_ID", tenant)
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    _assert_closed(r)
    assert r["reason"] == "tenant_setting_invalid"
    assert transport == []


# ---- success shapes -------------------------------------------------------------------------------------------
def test_inspect_oversight_case_returns_only_the_report(configured, transport):
    transport.set(lambda request: httpx.Response(200, json={
        "mode": "SUPPLIED_RECORDS_CHECK", "can_write": False, "can_execute": False, "trust_basis": "caller claims",
        "status": "OK", "viewer_tenant": TENANT, "report": {"overall": "NOT_READY"}, "pause": {"verdict": "X"}}))
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    assert r["status"] == "OK" and r["read_only"] is True
    assert r["data"]["report"] == {"overall": "NOT_READY"}
    assert "pause" not in r["data"] and r["data"]["trust_basis"] == "caller claims"


def test_get_intervention_evidence_returns_only_the_pause_section(configured, transport):
    transport.set(lambda request: httpx.Response(200, json={"report": {"overall": "R"}, "pause": {"verdict": "V"}}))
    r = api_ops.call("get_intervention_evidence", {"x": 1})
    assert r["status"] == "OK"
    assert r["data"]["pause"] == {"verdict": "V"} and "report" not in r["data"]


@pytest.mark.parametrize("op", [o for o, s in api_ops.OPERATIONS.items() if s["field"] is None])
def test_whole_answer_operations_pass_the_answer_through_unchanged(configured, transport, op):
    answer = {"status": "OK", "executed": False, "signed": False, "graph_writes": 0, "rows": [1, 2]}
    transport.set(lambda request: httpx.Response(200, json=answer))
    r = api_ops.call(op, {"x": 1})
    assert r["status"] == "OK" and r["data"] == answer and r["operation"] == op
    assert "not a compliance finding" in r["notice"]


def test_the_two_surfaces_are_the_ones_the_tools_name():
    assert {s["path"].split("/")[2] for s in api_ops.OPERATIONS.values()} == {"outcome-harness", "signal-intel"}
    assert len(api_ops.OPERATIONS) == 9
    assert all(s["path"].startswith("/internal/") for s in api_ops.OPERATIONS.values())


# ---- through the MCP server -------------------------------------------------------------------------------------
def test_the_tools_are_registered_read_only_and_say_so():
    pytest.importorskip("mcp")
    from trust_gate_mcp import server as srv
    desc = {t["name"]: t["description"] for t in srv.describe_tools(srv.build_server())}
    for op in ALL_OPS:
        assert op in desc
        text = desc[op]
        assert "Read-only" in text and "not a compliance finding" in text
        assert "never from an argument" in text and "UNAVAILABLE" in text


def test_a_registered_tool_runs_end_to_end_and_is_unavailable_when_unset(transport, monkeypatch):
    pytest.importorskip("mcp")
    import asyncio
    from trust_gate_mcp import server as srv
    for name in ("TRUST_GATE_API_URL", "TRUST_GATE_API_KEY", "TRUST_GATE_TENANT_ID"):
        monkeypatch.delenv(name, raising=False)
    mcp = srv.build_server()
    out = asyncio.run(mcp.call_tool("inspect_oversight_case", {"request": {"x": 1}}))
    text = json.dumps(out if isinstance(out, (dict, list)) else str(out), default=str)
    assert "UNAVAILABLE" in text and "not_configured" in text
    assert transport == []


def test_the_tool_input_schema_has_one_object_argument_and_no_tenant():
    pytest.importorskip("mcp")
    import asyncio
    from trust_gate_mcp import server as srv
    tools = {t.name: t for t in asyncio.run(srv.build_server().list_tools())}
    for op in ALL_OPS:
        props = tools[op].inputSchema["properties"]
        assert list(props) == ["request"]
        assert props["request"]["type"] == "object"
