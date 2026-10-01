"""test_behaviour_details.py -- small behaviours that each deserve their own assertion."""
from __future__ import annotations

import asyncio
import copy
import json

import pytest

from trust_gate_mcp import bootstrap
from trust_gate_mcp import server as srv

needs_oao = pytest.mark.skipif(srv._oao_receipt is None, reason="openagentontology not available in this env")


def assess(action, resource="docs"):
    return srv._gate_assessment(action, resource)


# ---- gate: tiers, reasons and small grammar rules ---------------------------------------------------------
def test_fullwidth_letters_fold_to_ascii_before_the_resource_is_judged():
    assert assess("read_file", "ｄｏｃｓ")["verdict"] == "ALLOW"                 # fullwidth "docs" is "docs"
    assert assess("read_file", "ｄｏｃｓ／．ｅｎｖ")["verdict"] == "ESCALATE"      # and a fullwidth ".env" is ".env"


def test_a_sensitive_word_with_a_risky_lead_verb_is_high_and_names_both_reasons():
    got = assess("write_secret", "x")
    assert got["tier"] == "HIGH" and got["verdict"] == "ESCALATE"
    assert len(got["reasons"]) == 2 and "medium-risk lead verb" in got["reasons"][1]
    got = assess("update_password", "x")
    assert got["tier"] == "HIGH" and any("lead verb" in r for r in got["reasons"])


def test_a_sensitive_word_without_any_lead_verb_is_still_high():
    got = assess("frobnicate", "passwords")
    assert got["tier"] == "HIGH" and got["verdict"] == "ESCALATE"


def test_a_resource_with_surrounding_spaces_is_one_word_after_a_query_verb():
    assert assess("query_db", " users ")["verdict"] == "ALLOW"
    assert assess("query_db", "users where")["verdict"] == "ESCALATE"


def test_digits_are_allowed_in_an_action_tail_but_letters_that_are_not_nouns_are_not():
    assert assess("get_user_2", "docs")["verdict"] == "ALLOW"
    assert assess("list_files_v2", "docs")["verdict"] == "ESCALATE"


def test_the_tier_scores_are_the_documented_ones():
    scores = {tier: assess(action)["score"] for tier, action in
              (("CRITICAL", "delete_file"), ("HIGH", "send_email"), ("MEDIUM", "update_file"), ("LOW", "read_file"))}
    assert scores == {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 10}
    assert assess("frobnicate")["score"] == 50 and assess("frobnicate")["tier"] == "UNKNOWN"


def test_a_risky_word_after_the_lead_counts_one_tier_lower_in_the_inventory_ranking():
    assert srv._tier_for_row("read_delete", "", "")[0] == "HIGH"       # critical, but not the lead
    assert srv._tier_for_row("read_flush", "", "")[0] == "MEDIUM"      # high, but not the lead
    assert srv._tier_for_row("delete_file", "", "")[0] == "CRITICAL"
    assert srv._tier_for_row("read_file", "", "")[0] == "LOW"


@needs_oao
def test_the_phase_may_carry_spaces_and_any_case_and_a_preview_id_must_be_text():
    pv = srv.tool_gate_decision("read_file", "docs", {}, phase="\tpreview\n")
    assert "error" not in pv and pv["phase"] == "PREVIEW"
    assert "error" not in srv.tool_gate_decision("read_file", "docs", {}, phase=" preview ")
    assert "error" in srv.tool_gate_decision("read_file", "docs", {}, phase="COMMIT", preview_id=123)
    assert "error" in srv.tool_gate_decision("read_file", "docs", {}, phase="PREVIEW\x00")


# ---- verify -------------------------------------------------------------------------------------------------
@needs_oao
def test_a_verifier_that_raises_for_any_reason_gives_a_clean_no(monkeypatch):
    def boom(_receipt):
        raise RuntimeError("/srv/secret/path/inside/the/primitive")
    monkeypatch.setattr(srv._oao_receipt, "verify_receipt", boom)
    out = srv.tool_verify_receipt({"decision": "ALLOW"})
    assert out["ok"] is False and "malformed" in out["reason"] and "secret" not in json.dumps(out)


@needs_oao
@pytest.mark.parametrize("drop", [("verify_pubkey_b64",), ("kid",), ("verify_pubkey_b64", "kid")])
def test_naming_the_signer_in_any_way_requires_the_signers_signature(drop):
    """A receipt names its Ed25519 signer by public key, by kid, or both. Whichever it uses, it must carry that
    key's own signature (here the signature is removed, and only the PQ signature remains)."""
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    stripped = copy.deepcopy(receipt)
    stripped["signature_b64"] = None
    for key in drop:
        stripped.pop(key)
    out = srv.tool_verify_receipt(stripped)
    names_a_signer = len(drop) < 2
    assert out["ok"] is (not names_a_signer), (drop, out)


@needs_oao
def test_a_key_without_a_kid_cannot_match_a_pin_even_with_a_valid_signature():
    """The Ed25519 signature verifies but the key is spelled non-canonically, so no kid exists: the pin must
    not be reported as matched."""
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    spelled = copy.deepcopy(receipt)
    spelled["verify_pubkey_b64"] += "\n"
    spelled["kid"] = ""
    out = srv.tool_verify_receipt(spelled, expected_kid=receipt["kid"])
    assert out["ok"] is False and out["signer_pinned"] is False and out.get("expected_kid_matched") is not True, out


@needs_oao
def test_signed_fields_lists_the_evidence_only_when_the_receipt_has_it():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    no_evidence = copy.deepcopy(receipt)
    no_evidence.pop("evidence")
    assert "evidence (through evidence_hash)" in srv.tool_verify_receipt(receipt)["signed_fields"]
    assert "evidence (through evidence_hash)" not in srv.tool_verify_receipt(no_evidence)["signed_fields"]


def test_the_pq_note_says_a_leg_does_not_identify_its_signer():
    note = srv._NOTE_PQ
    assert "does not say who holds that key" in note and "Pin the" in note
    assert "proves the signer" not in note


# ---- record changes and descriptions ---------------------------------------------------------------------
@needs_oao
@pytest.mark.parametrize("args", [("", "Person", "name"), ("r1", "", "name"), ("r1", "Person", "")])
def test_a_record_change_needs_its_id_type_and_field(args):
    out = srv.tool_mint_receipt_for_record_change(*args, "old", "new", "agent-1")
    assert "error" in out


@needs_oao
def test_the_tool_descriptions_state_what_each_tool_does_not_do():
    pytest.importorskip("mcp")
    tools = {t["name"]: t["description"] for t in srv.describe_tools(srv.build_server())}
    assert "cannot block anything itself" in tools["check_egress"]
    assert "WITHHELD_PENDING_HUMAN" in tools["gate_decision"] and "DENIED" in tools["gate_decision"]
    verify = tools["verify_receipt"].lower()
    assert "not" in verify and "who signed" in verify
    assert "kid consistent with the embedded key" in verify and "proves who signed" not in verify


# ---- check_egress edges --------------------------------------------------------------------------------------
@needs_oao
def test_egress_inputs_are_capped_exactly_and_typed():
    assert "error" not in srv.tool_check_egress("https://x.example", "a" * 65536, "prov")
    assert "error" in srv.tool_check_egress("https://x.example", "a" * 65537, "prov")
    assert "error" in srv.tool_check_egress("https://x.example", "hello", 5)
    assert "error" in srv.tool_check_egress("https://x.example", 5, "prov")


@pytest.mark.parametrize("third, expected", [("abcdefghij", True), ("abcdefghi", False), ("abc", False)])
def test_a_json_web_token_needs_three_substantial_segments(third, expected):
    token = f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{third}"
    assert srv._has_jwt(token) is expected


@needs_oao
@pytest.mark.parametrize("sample", ["sk-proj-abcdefghijklmnopqrstuvwx", "sk-ant-api03-abcdefghijklmnopqrstuv"])
def test_a_bare_hyphenated_api_key_is_restricted(sample):
    out = srv.tool_check_egress("https://x.example", f"the key is {sample} ok", "prov")
    assert (out["classification"], out["blocked"]) == ("RESTRICTED", True)


@needs_oao
@pytest.mark.parametrize("sample", ["check the passwd file", "a pwd reset link", "please send the passwords"])
def test_credential_words_alone_are_confidential_not_blocked(sample):
    out = srv.tool_check_egress("https://x.example", sample, "prov")
    assert (out["classification"], out["blocked"]) == ("CONFIDENTIAL", False), out


def test_only_this_machine_is_a_local_model_host_not_every_interface():
    assert srv._is_local_endpoint("0.0.0.0") is False
    assert srv._is_local_endpoint("http://0.0.0.0:11434") is False


# ---- rate-limiter classification and replay ---------------------------------------------------------------------
def _limiter():
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    return RateLimitMiddleware(app=None)


def test_only_a_tool_call_names_a_tool_for_classification():
    mw = _limiter()
    other = '{"method":"tools/list","params":{"name":"gate_decision"}}'
    assert mw._bucket_for(other)[0] is mw._default_buckets
    assert mw._bucket_for('{"method":"tools/call","params":{"name":"gate_decision"}}')[0] is mw._mint_buckets


def test_a_tool_name_that_is_not_text_is_ignored_not_fatal():
    mw = _limiter()
    for name in (["gate_decision"], {"x": 1}, 5, None):
        body = json.dumps({"method": "tools/call", "params": {"name": name}})
        assert mw._bucket_for(body)[0] is mw._default_buckets, name


def test_a_body_that_is_not_json_is_charged_to_the_signing_budget():
    mw = _limiter()
    for body in ("junk mint_ and verify_ junk", "junk verify_ only", "junk", b"\xff\xfe junk"):
        assert mw._bucket_for(body)[0] is mw._mint_buckets, body
    assert mw._bucket_for("")[0] is mw._default_buckets


def test_a_padded_verify_call_is_charged_to_the_signing_budget(monkeypatch):
    """A body over the parse cap is classified as signing, so padding a cheap call cannot buy a bigger budget."""
    pytest.importorskip("httpx")
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "2")
    monkeypatch.setenv("RATE_LIMIT_VERIFY_PER_MIN", "50")
    monkeypatch.setenv("RATE_LIMIT_DEFAULT_PER_MIN", "50")

    async def ok(_request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", ok, methods=["POST"])], middleware=[Middleware(RateLimitMiddleware)])
    padded = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "verify_receipt", "arguments": {"receipt": {"pad": "x" * (RateLimitMiddleware.MAX_BODY_BYTES + 100)}}}})
    client = TestClient(app, client=("4.4.4.4", 40000))
    codes = [client.post("/mcp", content=padded, headers={"content-type": "application/json"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    small = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "verify_receipt", "arguments": {}}})
    assert client.post("/mcp", content=small, headers={"content-type": "application/json"}).status_code == 200


def test_after_the_body_the_application_still_hears_the_servers_next_message():
    """The limiter replays the buffered body once, then passes receive() through: a disconnect must arrive."""
    from trust_gate_mcp.rate_limit import RateLimitMiddleware
    seen = []
    script = [{"type": "http.request", "body": b"abc", "more_body": True},
              {"type": "http.request", "body": b"def", "more_body": False},
              {"type": "http.disconnect"}]

    async def app(scope, receive, send):
        seen.append(await receive())
        seen.append(await receive())

    async def receive():
        return script.pop(0)

    async def send(_message):
        pass

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": [], "query_string": b"",
             "client": ("9.9.9.9", 1), "scheme": "http", "server": ("t", 80), "http_version": "1.1"}
    asyncio.run(RateLimitMiddleware(app)(scope, receive, send))
    assert seen[0] == {"type": "http.request", "body": b"abcdef", "more_body": False}
    assert seen[1] == {"type": "http.disconnect"}


# ---- the landing page and the bootstrap --------------------------------------------------------------------------
def test_the_landing_page_states_the_real_tool_count(monkeypatch):
    pytest.importorskip("httpx")
    import importlib
    import pathlib
    import trust_gate_mcp
    from starlette.testclient import TestClient
    monkeypatch.syspath_prepend(str(pathlib.Path(trust_gate_mcp.__file__).resolve().parent))
    http = importlib.import_module("server_http")
    with TestClient(http.build_app(), client=("8.8.4.4", 40000)) as client:
        page = client.get("/", headers={"accept": "text/html"}).text
    assert "7 tools" in page and "seven" not in page.lower().replace("seven tools", "")


@needs_oao
def test_bootstrap_refuses_to_start_when_the_live_kid_cannot_be_derived(tmp_path, monkeypatch, capsys):
    key = tmp_path / "receipt_ed25519.pem"
    bootstrap.ensure_keys_and_metadata(key_path=str(key))             # writes metadata with a kid
    monkeypatch.setattr(bootstrap, "_kid_for_pubkey_b64", lambda _pub: "")
    with pytest.raises(SystemExit) as exc:
        bootstrap.ensure_keys_and_metadata(key_path=str(key))
    assert exc.value.code == 78
    assert "could not derive live key kid" in capsys.readouterr().err      # not the drift message
