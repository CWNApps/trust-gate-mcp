"""test_api_ops_hardening.py -- proxy, redirects, headers, nested tenant keys and capped bodies for the API views.

Mocked HTTP only; nothing here reaches a network.
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


def _closed(result, status):
    assert result["status"] == status and result["data"] is None and result["read_only"] is True


def test_the_production_client_ignores_proxy_environment_variables(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://proxy.example.test:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    # negative control: a client that trusts the environment DOES pick the proxy up
    with httpx.Client(trust_env=True) as control:
        assert control._mounts, "the control client should have proxy mounts with HTTP_PROXY set"
    with api_ops._client_factory(api_ops.TIMEOUT_SECONDS) as client:
        assert client._mounts == {}
        assert client._trust_env is False


def test_the_production_client_does_not_follow_redirects_and_has_a_timeout():
    with api_ops._client_factory(api_ops.TIMEOUT_SECONDS) as client:
        assert client.follow_redirects is False
        assert client.timeout.read == api_ops.TIMEOUT_SECONDS


@pytest.mark.parametrize("op", ALL_OPS)
def test_the_credential_is_in_no_header_but_authorization(configured, transport, op):
    api_ops.call(op, {"x": 1})
    for name, value in transport[0].headers.items():
        if name.lower() != "authorization":
            assert SECRET not in value, name
    assert transport[0].headers["authorization"] == "Bearer " + SECRET


@pytest.mark.parametrize("key", ["Tenant_ID", "TENANT", "tenantid", "tenant-id", "TenantId", "TENANT-ID", "tenant_Id"])
@pytest.mark.parametrize("op", ALL_OPS)
def test_a_top_level_tenant_key_in_any_spelling_is_refused(configured, transport, op, key):
    r = api_ops.call(op, {key: TENANT, "x": 1})
    _closed(r, "REFUSED")
    assert r["reason"] == "tenant_is_configuration_not_an_argument"
    assert transport == []


@pytest.mark.parametrize("nested", [
    {"records": [{"id": "r1", "Tenant-Id": "someone-else"}]},
    {"a": {"b": {"c": [{"TENANT": "someone-else"}]}}},
    {"facts": [{"tenantId": "someone-else"}]},
    {"receipt": {"tenant_id": 7}},
    {"receipt": {"tenant": None}},
    {"receipt": {"tenant_id": {"x": 1}}},
])
def test_a_nested_tenant_key_naming_another_tenant_is_refused_at_any_depth(configured, transport, nested):
    r = api_ops.call("get_receipt_evidence", nested)
    _closed(r, "REFUSED")
    assert r["reason"] == "tenant_is_configuration_not_an_argument"
    assert transport == []


def test_a_nested_record_that_names_the_configured_tenant_is_allowed(configured, transport):
    # a record carries its own owner; it must equal the configured tenant, so it can never name another
    r = api_ops.call("get_receipt_evidence", {"receipt": {"tenant_id": TENANT, "id": "r1"}, "facts": [{"Tenant": TENANT}]})
    assert r["status"] == "OK"
    assert len(transport) == 1


def test_tenant_like_text_in_a_value_or_a_longer_key_is_not_a_tenant_key(configured, transport):
    r = api_ops.call("replay_decision", {"note": "tenant_id someone-else", "tenantry": "x"})
    assert r["status"] == "OK"


def test_a_deeply_nested_request_is_refused_and_never_crashes(configured, transport):
    deep = cur = {}
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    r = api_ops.call("replay_decision", deep)
    assert r["status"] in ("REFUSED", "UNAVAILABLE") and r["data"] is None
    assert transport == []


def test_an_error_body_is_read_for_at_most_4_kib(configured, transport):
    big = json.dumps({"code": "PAD", "pad": "x" * 20000}).encode()
    transport.set(lambda request: httpx.Response(400, content=big))
    r = api_ops.call("inspect_oversight_case", {"x": 1})
    _closed(r, "REFUSED")
    assert "code" not in r
    transport.set(lambda request: httpx.Response(400, content=json.dumps({"code": "SMALL"}).encode()))
    assert api_ops.call("inspect_oversight_case", {"x": 1})["code"] == "SMALL"


def test_a_300_body_is_not_read_beyond_the_cap_either(configured, transport):
    transport.set(lambda request: httpx.Response(302, content=b"x" * 50000, headers={"location": "https://e.example.test/"}))
    _closed(api_ops.call("inspect_oversight_case", {"x": 1}), "REFUSED")


def test_a_streamed_success_body_over_the_cap_is_never_fully_read(configured, monkeypatch):
    chunk = 100 * 1024
    read = {"n": 0}

    def gen():
        for _ in range(100):
            read["n"] += chunk
            yield b"x" * chunk

    def factory(timeout):
        return httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=gen())), timeout=timeout)

    monkeypatch.setattr(api_ops, "_client_factory", factory)
    r = api_ops.call("replay_decision", {"x": 1})
    _closed(r, "UNAVAILABLE")
    assert r["reason"] == "response_too_large"
    assert read["n"] < 100 * chunk


def test_descriptions_say_the_server_version_must_serve_the_view():
    pytest.importorskip("mcp")
    from trust_gate_mcp import server as srv
    desc = {t["name"]: t["description"] for t in srv.describe_tools(srv.build_server())}
    for op in ALL_OPS:
        assert "UNAVAILABLE until" in desc[op] and "version" in desc[op]
