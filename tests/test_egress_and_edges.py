"""test_egress_and_edges.py -- credential spellings for check_egress, and edge behaviour of the other tools."""
from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import time

import pytest

from trust_gate_mcp import server as srv

needs_oao = pytest.mark.skipif(srv._oao_receipt is None, reason="openagentontology not available in this env")


# ---- credential-shaped values are RESTRICTED and blocked, in the spellings people really write ----------
RESTRICTED_SAMPLES = [
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    'export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuv",
    "PGPASSWORD=hunter2", "DBPASSWORD=hunter2", "MYSQL_PWD=hunter2", "PASSWD=hunter2", "DB_PASSWORD=hunter2",
    "SECRET_KEY=django-insecure-abc", "password: 'correct-horse'", "client_secret = abcdef123456",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----BEGIN RSA PRIVATE KEY-----",
    "Authorization: Basic dXNlcjpodW50ZXIy", "authorization=Bearer abcdefgh12345678",
    "glpat-abcdefghijklmnopqrstuvwx", "ya29.a0AbcdefghijklmnopqrstuvWXYZ", "hf_" + "a" * 34, "npm_" + "b" * 36,
    "pypi-" + "c" * 60, "SG." + "d" * 22 + "." + "e" * 22, "rk_live_abcdefghij1234", "sk_test_abcdefghij1234",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij",
    "xoxb-1234567890-abcdefgh", "AKIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz", "github_pat_" + "A" * 30,
    "postgres://admin:hunter2@db.example:5432/prod", "AIzaSyA-1234567890abcdefghijklmnopqrstuv",
    "DB_PASS=hunter2hunter2", "PASS=hunter2hunter2", "MASTER_KEY=9f8e7d6c5b4a3210", "ENCRYPTION_KEY=abcdef123456",
    "HMAC_KEY=abcdef123456", "SESSION_KEY=abcdef123456", "STRIPE_KEY=abcdef123456", "KEY=abcdef123456",
    "AUTH_TOKEN=abcdef12345", "GITHUB_TOKEN=9f8e7d6c5b4a3210", "SIGNING_KEY=abcdef123456", "ACCESS_KEY=abcdef123456",
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
    "redis://:hunter2secret@cache.example:6379/0", "REDIS_URL=redis://:hunter2secret@cache.example:6379",
    '{"password": "hunter2hunter2"}', '{"api_key":"Zx81kq0Pqw7Lm2Vb"}', "{'client_secret': '9f8e7d6c5b4a'}",
    '{"db_pass": "hunter2hunter2", "user": "app"}',
    "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000000/B000000/XXXXXXXXXXXXXXXX",
    "PuTTY-User-Key-File-3: ssh-rsa", "4111.1111.1111.1111",
]


@needs_oao
@pytest.mark.parametrize("sample", RESTRICTED_SAMPLES)
def test_credential_shaped_values_are_restricted_and_blocked(sample):
    out = srv.tool_check_egress("https://x.example", sample, "prov")
    assert (out["classification"], out["blocked"]) == ("RESTRICTED", True), out


@needs_oao
@pytest.mark.parametrize("sample, classification", [
    ("the bearer of this message", "CONFIDENTIAL"),
    ("max_tokens=1000", "CONFIDENTIAL"),
    ("please rotate the api key", "CONFIDENTIAL"),
    ("password: true", "CONFIDENTIAL"),
    ("draft roadmap for next quarter", "INTERNAL"),
    ("the quarterly numbers look fine", "NO_MARKERS_FOUND"),
])
def test_keywords_alone_do_not_block(sample, classification):
    out = srv.tool_check_egress("https://x.example", sample, "prov")
    assert (out["classification"], out["blocked"]) == (classification, False), out


@needs_oao
def test_a_credential_in_the_provider_field_is_classified_and_never_echoed_or_signed():
    key = "AKIAIOSFODNN7EXAMPLE"
    out = srv.tool_check_egress("https://x.example", "hello world", key)
    assert out["classification"] == "RESTRICTED" and out["blocked"] is True
    assert key not in json.dumps(out), "the credential was echoed or signed in clear text"
    assert out["provider"].startswith("[withheld")
    assert "error" in srv.tool_check_egress("https://x.example", "hello", "p" * 201)


@needs_oao
def test_the_classifier_stays_linear_on_glued_secret_names():
    samples = ["password" * 8192, "PASSWORD_" * 7000, "a" * 65000, "secret_" + "x" * 60000, "pwd=" * 16000,
               "api_key: " * 7000, "eyJ" * 20000, "1234 " * 12000,
               "1 " * 32000, "1." * 32000, "1111111 " * 8000, ("1" * 19 + " ") * 3200]
    for text in samples:
        started = time.perf_counter()
        srv._classify_egress(text, "dest")
        assert time.perf_counter() - started < 2.0, text[:20]


def test_card_numbers_need_a_valid_check_digit_and_a_plausible_length():
    assert srv._has_card_number("4111 1111 1111 1111")
    assert srv._has_card_number("4222222222222")                  # 13 digits
    assert srv._has_card_number("6011000000000004")
    assert not srv._has_card_number("4111 1111 1111 1112")        # wrong check digit
    assert not srv._has_card_number("411111111111")               # 12 digits


# ---- reserved names ---------------------------------------------------------------------------------------
@needs_oao
@pytest.mark.parametrize("decision", ["ALL0W", "GR4NTED", "PERM1T", "D3NY", "ESC4LATE", "A11OW", "AUTO_APPROVE",
                                      "approve", "APPROVED_BY_HUMAN", "DENY!", "gr@nted"])
def test_a_verdict_word_written_with_swapped_characters_is_still_reserved(decision):
    assert "error" in srv.tool_mint_action_receipt("agent", "deploy", "prod", decision=decision)


@needs_oao
@pytest.mark.parametrize("operation", ["g4te_commit", "decision_g@te_commit", "decisiong4te", "trust-g4te", "DECISION.GATE",
                                       "gate", "gateVerdict"])
def test_an_operation_that_reads_as_the_gates_own_is_reserved(operation):
    assert "error" in srv.tool_mint_action_receipt("agent", operation, "prod", decision="EXECUTED")


@needs_oao
def test_ordinary_action_receipts_are_not_refused():
    out = srv.tool_mint_action_receipt("agent-1", "deploy_service", "svc-a", decision="EXECUTED")
    assert "error" not in out and out["decision"] == "EXECUTED"


@needs_oao
def test_the_inputs_are_bound_into_the_receipt():
    one = srv.tool_mint_action_receipt("agent", "transfer", "acct", inputs="amount=1")
    many = srv.tool_mint_action_receipt("agent", "transfer", "acct", inputs="amount=1000000")
    same = srv.tool_mint_action_receipt("agent", "transfer", "acct", inputs="amount=1")
    assert one["evidence_hash"] != many["evidence_hash"]
    assert one["evidence_hash"] == same["evidence_hash"]
    assert srv._ascii_hash("amount=1") in json.dumps(one)
    assert srv._ascii_hash("amount=1000000") in json.dumps(many)


@needs_oao
def test_a_signing_failure_is_an_opaque_error_without_a_path(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("[Errno 13] Permission denied: '/srv/hidden-dir/keys/receipt_ed25519.pem'")
    monkeypatch.setattr(srv._oao_receipt, "mint_receipt", boom)
    out = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    assert out["error"] == "mint_failed" and "hidden-dir" not in json.dumps(out)
    gate = srv.tool_gate_decision("read_file", "docs", {}, phase="PREVIEW")
    committed = srv.tool_gate_decision("read_file", "docs", {}, phase="COMMIT", preview_id=gate["preview_id"])
    assert committed["permit"] == "NOT_ISSUED" and "hidden-dir" not in json.dumps(committed)


# ---- verify_receipt edges -------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["a string", ["a", "list"], 5, None, True])
def test_verify_receipt_refuses_anything_that_is_not_an_object(value):
    out = srv.tool_verify_receipt(value)
    assert out["ok"] is False and "JSON object" in out["reason"]


@needs_oao
def test_signed_fields_lists_only_what_the_receipt_actually_carries():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    full = srv.tool_verify_receipt(receipt)
    assert full["signed_fields"] == ["atom_id", "type", "decision", "evidence_hash", "signed_at",
                                     "evidence (through evidence_hash)"]
    trimmed = copy.deepcopy(receipt)
    for key in ("atom_id", "type", "signed_at"):
        trimmed.pop(key)
    assert srv.tool_verify_receipt(trimmed)["signed_fields"] == ["decision", "evidence_hash",
                                                                  "evidence (through evidence_hash)"]


# ---- the exit drill -------------------------------------------------------------------------------------
@pytest.mark.parametrize("value, local", [
    ("localhost:11434", True), ("http://127.0.0.1:11434", True), ("http://[::1]:11434", True), ("::1", False),
    ("unix:/tmp/ollama.sock", True), ("http://example.com:11434", False), ("http://localhost.evil.example", False),
    ("", False),
])
def test_only_this_machine_counts_as_a_local_model_host(value, local):
    assert srv._is_local_endpoint(value) is local


@needs_oao
def test_the_drill_reports_the_host_and_never_the_credentials_or_the_query(monkeypatch):
    monkeypatch.setattr(srv, "_pq_backend", lambda: "liboqs")
    monkeypatch.setenv("OLLAMA_HOST", "http://user:pw-secret@example.com:11434/api/x?token=abc123")
    out = srv.tool_run_exit_drill()
    detail = json.dumps(out["steps"])
    assert "example.com:11434" in detail and "pw-secret" not in detail and "abc123" not in detail
    assert out["readiness"] == "PARTIAL" and out["passed"] == 1 and out["total"] == 2


@needs_oao
def test_the_drill_is_ready_only_when_every_check_passes(monkeypatch):
    monkeypatch.setattr(srv, "_pq_backend", lambda: "liboqs")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    assert srv.tool_run_exit_drill()["readiness"] == "READY"
    monkeypatch.delenv("OLLAMA_HOST")
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    unknown = srv.tool_run_exit_drill()
    assert unknown["readiness"] == "PARTIAL" and unknown["passed"] == 1
    monkeypatch.setattr(srv, "_pq_backend", lambda: "dilithium_py")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    assert srv.tool_run_exit_drill()["readiness"] == "PARTIAL"     # the pure-Python backend is a warning, not a pass


def test_endpoint_labels_keep_scheme_host_and_port_only():
    assert srv._endpoint_label("http://u:p@example.com:11434/a/b?c=d") == "http://example.com:11434"
    assert srv._endpoint_label("example.com:11434") == "example.com:11434"
    assert srv._endpoint_label("http://[::1]:11434") == "http://[::1]:11434"
    assert srv._endpoint_label("http://") == "[unparseable]"
    assert srv._endpoint_label("http://h:notaport") == "[unparseable]"


# ---- the provider field, the receipt note, what verify echoes, the exit drill ---------------------------------------
@needs_oao
@pytest.mark.parametrize("provider", ["123-45-6789", "4111111111111111", "AKIAIOSFODNN7EXAMPLE",
                                      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij", "password=hunter2hunter2"])
def test_a_sensitive_provider_is_withheld_from_the_response_and_the_signed_receipt(provider):
    out = srv.tool_check_egress("https://x.example", "hello world", provider)
    assert out["provider"].startswith("[withheld") and provider not in json.dumps(out), out
    assert out["classification"] == "RESTRICTED" and out["blocked"] is True


@needs_oao
def test_an_ordinary_provider_is_recorded_as_given():
    out = srv.tool_check_egress("https://x.example", "hello world", "acme-llm")
    assert out["provider"] == "acme-llm" and "acme-llm" in json.dumps(out["receipt"])


@needs_oao
def test_the_note_only_claims_a_post_quantum_signature_when_one_exists(monkeypatch):
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    assert receipt["note_pq"] == srv._NOTE_PQ and "ML-DSA-65" in receipt["note_pq"]
    real = srv._oao_receipt.mint_receipt

    def classical_only(manifest, **kw):
        out = real(manifest, **kw)
        for key in ("ml_dsa_signature_b64", "ml_dsa_public_key_b64", "slh_dsa_signature_b64", "slh_dsa_public_key_b64"):
            out.pop(key, None)
        return out
    monkeypatch.setattr(srv._oao_receipt, "mint_receipt", classical_only)
    plain = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    assert plain["note_pq"] == srv._NOTE_NO_PQ and "no post-quantum signature" in plain["note_pq"]


@needs_oao
def test_verify_echoes_the_values_it_verified_and_nothing_when_it_refuses():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a", decision="EXECUTED")
    out = srv.tool_verify_receipt(receipt)
    assert out["ok"] is True
    assert out["verified"]["decision"] == "EXECUTED" and out["verified"]["issuer_tool"] == "mint_action_receipt"
    assert out["verified"]["operation"] == "deploy_service" and out["verified"]["evidence_hash"] == receipt["evidence_hash"]
    tampered = copy.deepcopy(receipt)
    tampered["decision"] = "ALLOW"
    assert "verified" not in srv.tool_verify_receipt(tampered)


@needs_oao
def test_the_drill_does_not_pass_the_signing_step_when_this_host_cannot_sign(monkeypatch):
    monkeypatch.setattr(srv, "_pq_backend", lambda: "liboqs")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    monkeypatch.setattr(srv, "_mint", lambda manifest, decision: {"error": "mint_failed"})
    out = srv.tool_run_exit_drill()
    assert out["steps"][0]["status"] == "FAIL" and out["readiness"] == "PARTIAL" and out["passed"] == 1
    assert "configured" in out["steps"][1]["description"] and "not contacted" in out["steps"][1]["description"]


# ---- notes, drill and verify details ----------------------------------------------------------------
@needs_oao
def test_the_note_says_so_when_there_is_no_ed25519_signature(monkeypatch):
    real = srv._oao_receipt.mint_receipt

    def pq_only(manifest, **kw):
        out = real(manifest, **kw)
        out["signature_b64"] = ""
        return out
    monkeypatch.setattr(srv._oao_receipt, "mint_receipt", pq_only)
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    assert receipt["note_pq"] == srv._NOTE_NO_ED and "post-quantum signatures only" in receipt["note_pq"]
    monkeypatch.setattr(srv, "_pq_backend", lambda: "liboqs")
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    drill = srv.tool_run_exit_drill()
    assert drill["steps"][0]["status"] == "FAIL" and drill["readiness"] == "PARTIAL"


@needs_oao
def test_the_verified_block_carries_the_manifest_and_not_the_unsigned_kid():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a", decision="EXECUTED")
    out = srv.tool_verify_receipt(receipt)
    assert out["verified"]["ontology"]["target"] == "svc-a" and out["verified"]["ontology"]["agent_id"] == "agent"
    assert "kid" not in out["verified"]
    assert set(out["verified"]) == {"atom_id", "type", "decision", "evidence_hash", "signed_at", "issuer_tool", "operation",
                                    "ontology"}


@needs_oao
def test_a_pin_and_a_receipt_kid_must_match_every_character():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    kid = receipt["kid"]
    other = kid[:-1] + ("0" if kid[-1] != "0" else "1")
    pinned = srv.tool_verify_receipt(receipt, expected_kid=other)
    assert pinned["ok"] is False and pinned["signer_pinned"] is False
    forged = copy.deepcopy(receipt)
    forged["kid"] = other
    assert srv.tool_verify_receipt(forged)["ok"] is False
    assert srv.tool_verify_receipt(receipt, expected_kid=kid)["signer_pinned"] is True


@needs_oao
def test_an_unverifiable_leg_is_not_listed_as_verified():
    receipt = srv.tool_mint_action_receipt("agent", "deploy_service", "svc-a")
    junk = copy.deepcopy(receipt)
    junk["slh_dsa_signature_b64"] = "AAAA"
    junk["slh_dsa_public_key_b64"] = "AAAA"
    out = srv.tool_verify_receipt(junk)
    if out["legs"].get("slh_dsa") != "ok":
        assert "hash-based" not in out["signature_alg"] and "hash-based" not in out["reason"], out


def test_the_egress_receipt_decision_names_the_class_not_an_enforcement():
    out = srv.tool_check_egress("https://x.example", "AKIAIOSFODNN7EXAMPLE", "prov")
    assert out["receipt"]["decision"] == "EGRESS_RESTRICTED"


def test_the_cheap_credential_and_birth_date_words_are_flagged():
    for sample, classification in (("pw=hunter2hunter2", "RESTRICTED"), ("the creds are in the vault", "CONFIDENTIAL"),
                                   ("birthdate 1980-01-01", "RESTRICTED"), ("card 4111_1111_1111_1111", "RESTRICTED")):
        assert srv._classify_egress(sample, "dest")[0] == classification, sample


def test_a_malformed_model_host_is_not_local_and_does_not_crash_the_drill(monkeypatch):
    assert srv._is_local_endpoint("http://[abc") is False
    monkeypatch.setenv("OLLAMA_HOST", "http://[abc")
    out = srv.tool_run_exit_drill()
    assert out["readiness"] == "PARTIAL" and out["steps"][1]["status"] == "UNKNOWN"



def _naive_luhn(digits: str) -> bool:
    """An independent Luhn check, written differently from the one under test."""
    total = 0
    for position, ch in enumerate(reversed(digits)):
        d = int(ch)
        if position % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _naive_group_window(groups):
    for i in range(len(groups)):
        for j in range(i + 1, len(groups) + 1):
            joined = "".join(groups[i:j])
            if 13 <= len(joined) <= 19 and _naive_luhn(joined):
                return True
    return False


def _with_check_digit(body: str) -> str:
    for c in "0123456789":
        if _naive_luhn(body + c):
            return body + c
    raise AssertionError("no check digit")


def test_the_window_scan_agrees_with_an_independent_luhn_on_random_group_lists():
    import random
    rng = random.Random(20261002)
    positives = 0
    for _ in range(4000):
        groups = ["".join(rng.choice("0123456789") for _ in range(rng.randint(1, 7))) for _ in range(rng.randint(1, 9))]
        if rng.random() < 0.4:           # plant a valid 13-19 digit number split into groups, with extra groups around it
            size = rng.randint(13, 19)
            card = _with_check_digit("".join(rng.choice("0123456789") for _ in range(size - 1)))
            cut = sorted(rng.sample(range(1, size), rng.randint(0, 4)))
            parts = [card[a:b] for a, b in zip([0] + cut, cut + [size])]
            groups = groups[: rng.randint(0, 2)] + parts + groups[: rng.randint(0, 2)]
        expected = _naive_group_window(groups)
        positives += expected
        assert srv._groups_hold_card_number(groups) == expected, groups
    assert positives > 400, positives     # the positive case is really exercised


@pytest.mark.parametrize("sample", ["4111 1111 1111 1111 123", "4111 1111 1111 1111 12/25", "4111-1111-1111-1111-123", "1 4111 1111 1111 1111",
                                    "2024-4111-1111-1111-1111", "3782 822463 10005 1234", "4111111111111111 123", "exp 12 25 card 5500 0000 0000 0004 123"])
def test_a_card_number_next_to_another_group_is_restricted(sample):
    assert srv._classify_egress(sample, "partner.example")[0] == "RESTRICTED", sample


@pytest.mark.parametrize("sample", ["4111 1111 1111 1112 123", "order 1696243200000000 shipped", "1111 1111 1111", "12 25 123 4111 1111", "4111111111111111111111 1"])
def test_other_digit_runs_are_not_taken_for_cards(sample):
    assert srv._classify_egress(sample, "partner.example")[0] == "NO_MARKERS_FOUND", sample
