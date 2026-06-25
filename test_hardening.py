"""test_hardening.py -- E2E tests for the four hardening items.

  H1 bootstrap     -- key + metadata file are written and the kid is stable across re-runs.
  H2 rate_limit    -- the token bucket caps a burst at its configured budget.
  H3 require_pq    -- PQ-required verify FAILS on a PQ-stripped receipt and PASSES on a clean one.
  H4 kid on every  -- every minted receipt carries a non-empty kid that equals sha256(pubkey)[:16].
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

import server as srv
from bootstrap import _kid_for_pubkey_b64, ensure_keys_and_metadata
from rate_limit import RateLimitMiddleware, TokenBucket

_HAS_OAO = srv._oao_receipt is not None


# ---- H4 kid on every receipt --------------------------------------------------------
@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h4_every_mint_carries_a_stable_kid():
    r1 = srv.tool_mint_action_receipt(agent_id="a", operation="o", target="t")
    r2 = srv.tool_mint_action_receipt(agent_id="b", operation="o2", target="t2")
    assert r1["kid"] and r2["kid"], "every mint must include a kid"
    # same notary, same key -> same kid even though everything else differs
    assert r1["kid"] == r2["kid"], "kid must be stable across mints with the same key"
    # kid = sha256(pubkey_b64)[:32] (128 bits -- codex-required for adversarial use)
    expected = hashlib.sha256(r1["verify_pubkey_b64"].encode("ascii")).hexdigest()[:32]
    assert r1["kid"] == expected
    assert len(r1["kid"]) == 32, "kid must be 128 bits (32 hex chars)"


@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h4_kid_is_inherited_by_all_four_tool_paths():
    r_change = srv.tool_mint_receipt_for_record_change(
        record_id="x", object_type="Person", field="email",
        old_value="a", new_value="b", changed_by_agent="agent")
    r_action = srv.tool_mint_action_receipt(agent_id="a", operation="o", target="t")
    aud = srv.tool_audit_my_agent_inventory([{"server": "g", "tool": "send", "capability": "send"}])
    # audit is read-only and returns no receipt itself, but if the caller mints one it inherits kid
    r_for_audit = srv.tool_mint_action_receipt(
        agent_id="x", operation="audit", target="x",
        inputs=str(aud["audit_manifest_for_receipt"]))
    kids = {r_change["kid"], r_action["kid"], r_for_audit["kid"]}
    assert len(kids) == 1 and next(iter(kids)), "all tools must share one kid (one notary)"


# ---- H3 PQ-required verify -----------------------------------------------------------
@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h3_pq_required_default_passes_full_pq_receipt():
    r = srv.tool_mint_action_receipt(agent_id="a", operation="o", target="t")
    # default require_pq (env-driven, default True) must accept a real PQ receipt
    v = srv.tool_verify_receipt(r)
    assert v["ok"] is True, v


@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h3_pq_required_rejects_pq_stripped_receipt():
    # simulate an attacker that stripped the PQ legs to leave Ed25519-only
    r = srv.tool_mint_action_receipt(agent_id="a", operation="o", target="t")
    stripped = copy.deepcopy(r)
    for k in ("ml_dsa_signature_b64", "ml_dsa_public_key_b64",
              "slh_dsa_signature_b64", "slh_dsa_public_key_b64"):
        stripped.pop(k, None)
    # default ON -> must FAIL because PQ legs are now absent
    v_strict = srv.tool_verify_receipt(stripped)
    assert v_strict["ok"] is False
    assert "PQ-required" in v_strict["reason"]
    # explicit opt-out still verifies via Ed25519 -- legacy mode
    v_legacy = srv.tool_verify_receipt(stripped, require_pq=False)
    assert v_legacy["ok"] is True


def test_h3_env_switch_off_relaxes_default(monkeypatch):
    # OAO_REQUIRE_PQ=false makes default lenient (Ed25519-only allowed by default)
    monkeypatch.setenv("OAO_REQUIRE_PQ", "false")
    assert srv._require_pq_default() is False
    monkeypatch.setenv("OAO_REQUIRE_PQ", "true")
    assert srv._require_pq_default() is True


# ---- H1 bootstrap + key_metadata.json -----------------------------------------------
@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h1_bootstrap_writes_metadata_and_kid_is_stable(tmp_path):
    keyfile = tmp_path / "receipt_ed25519.pem"
    m1 = ensure_keys_and_metadata(key_path=str(keyfile))
    metafile = tmp_path / "key_metadata.json"
    assert metafile.exists(), "bootstrap must write key_metadata.json"
    meta = json.loads(metafile.read_text(encoding="utf-8"))
    assert meta["kid"] == m1["kid"]
    assert meta["algorithms"]  # at least Ed25519
    # second run = idempotent, no rewrite, same kid
    m2 = ensure_keys_and_metadata(key_path=str(keyfile))
    assert m2["kid"] == m1["kid"]
    meta_after = json.loads(metafile.read_text(encoding="utf-8"))
    assert meta_after["created_at"] == meta["created_at"], "metadata must not be rewritten on idempotent re-run"


@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h1_bootstrap_fails_closed_on_kid_drift(tmp_path):
    keyfile = tmp_path / "receipt_ed25519.pem"
    ensure_keys_and_metadata(key_path=str(keyfile))
    # forge the on-disk metadata with a different kid -> live key kid won't match -> abort
    metafile = tmp_path / "key_metadata.json"
    forged = json.loads(metafile.read_text(encoding="utf-8"))
    forged["kid"] = "0000000000000000"
    metafile.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        ensure_keys_and_metadata(key_path=str(keyfile))
    assert exc.value.code == 78  # EX_CONFIG


def test_h1_kid_helper_matches_server_kid():
    # both helpers must produce the same kid for the same pubkey -- shared algorithm
    pub = "TESTPUBKEYB64=="
    assert _kid_for_pubkey_b64(pub) == hashlib.sha256(pub.encode("ascii")).hexdigest()[:32]
    assert len(_kid_for_pubkey_b64(pub)) == 32


@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h1_bootstrap_fails_closed_on_unreadable_metadata(tmp_path):
    # codex's fix #2: unreadable metadata must be FATAL, not a warn-and-continue
    keyfile = tmp_path / "receipt_ed25519.pem"
    ensure_keys_and_metadata(key_path=str(keyfile))
    metafile = tmp_path / "key_metadata.json"
    metafile.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        ensure_keys_and_metadata(key_path=str(keyfile))
    assert exc.value.code == 78


@pytest.mark.skipif(not _HAS_OAO, reason="OAO not available")
def test_h1_bootstrap_fails_closed_on_missing_kid_field(tmp_path):
    # codex's fix #2: metadata missing the kid field must be FATAL too
    keyfile = tmp_path / "receipt_ed25519.pem"
    ensure_keys_and_metadata(key_path=str(keyfile))
    metafile = tmp_path / "key_metadata.json"
    metafile.write_text(json.dumps({"created_at": "x", "algorithms": []}),
                        encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        ensure_keys_and_metadata(key_path=str(keyfile))
    assert exc.value.code == 78


# ---- H2 token-bucket rate limit ------------------------------------------------------
def test_h2_token_bucket_caps_at_capacity():
    b = TokenBucket(capacity=3, window_seconds=60.0)
    assert b.take() and b.take() and b.take(), "first 3 should succeed"
    assert not b.take(), "4th must fail (bucket empty within 60s)"


def test_h2_token_bucket_refills_proportionally(monkeypatch):
    # Use a 1-second window to keep the test fast; refill rate = 3 tokens/sec.
    b = TokenBucket(capacity=3, window_seconds=1.0)
    for _ in range(3):
        b.take()
    assert not b.take(), "empty after 3 takes"
    # advance the bucket's monotonic clock by 0.5s -> should refill ~1.5 tokens
    b.last -= 0.5
    assert b.take(), "should have refilled enough for one take after 0.5s"


def test_h2_middleware_classifies_by_body_keywords():
    # the bucket-picker uses simple substring tests; verify mint vs verify vs default
    mw = RateLimitMiddleware(app=None)
    buckets, cap = mw._bucket_for('{"method":"tools/call","params":{"name":"mint_action_receipt"}}')
    assert buckets is mw._mint_buckets and cap == mw.mint_cap
    buckets, cap = mw._bucket_for('{"method":"tools/call","params":{"name":"verify_receipt"}}')
    assert buckets is mw._verify_buckets and cap == mw.verify_cap
    buckets, cap = mw._bucket_for('{"method":"initialize"}')
    assert buckets is mw._default_buckets and cap == mw.default_cap


def test_h2_env_overrides_budgets(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_MINT_PER_MIN", "5")
    monkeypatch.setenv("RATE_LIMIT_VERIFY_PER_MIN", "50")
    mw = RateLimitMiddleware(app=None)
    assert mw.mint_cap == 5 and mw.verify_cap == 50


def test_h2_bucket_dict_is_bounded_against_ip_rotation_attack():
    # codex's fix #3: an attacker rotating IPs cannot grow the dict without limit.
    mw = RateLimitMiddleware(app=None)
    mw.MAX_BUCKETS_PER_CLASS = 100  # shrink for a fast test
    for i in range(250):
        mw._get_or_create(mw._mint_buckets, f"10.0.0.{i}", mw.mint_cap)
    assert len(mw._mint_buckets) <= 100, f"bucket dict grew unbounded: {len(mw._mint_buckets)}"
    # the most recent IP must still be present (FIFO -- oldest evicted, not random)
    assert "10.0.0.249" in mw._mint_buckets
