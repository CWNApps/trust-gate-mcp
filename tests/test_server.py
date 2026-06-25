"""test_server.py -- E2E tests for the Trust Gate MCP server.

Tests the pure tool functions directly (the FastMCP wiring is a thin decorator layer; the
mcp package is only needed to actually run the server, not to unit-test the tools). Proves:

  1. Each tool mints a receipt that verifies from the cert alone.
  2. Receipts carry the post-quantum legs (Ed25519 + ML-DSA-65 + SLH-DSA) when the PQ
     backend is installed -- the standing directive.
  3. Tamper detection: a one-field edit to the action breaks verification.
  4. The audit tool refuses to claim auto-discovery -- the honest-scope note is in every
     response and the receipt commits to the caller-provided input.
  5. The build_server() factory wires four tools when the mcp package is installed.
"""
from __future__ import annotations

import copy

import pytest

import server as srv


# the OAO receipt path must resolve (either installed or via the repo fallback in server.py)
_HAS_OAO = srv._oao_receipt is not None


# ---- mint_receipt_for_record_change --------------------------------------------------
@pytest.mark.skipif(not _HAS_OAO, reason="openagentontology not available in this env")
def test_record_change_mints_pq_receipt_and_verifies():
    r = srv.tool_mint_receipt_for_record_change(
        record_id="opp-123", object_type="Opportunity", field="stage",
        old_value="discovery", new_value="closed_won",
        changed_by_agent="relaticle-ai@tenant",
    )
    assert "error" not in r
    # the post-quantum legs must be present (PQ by default)
    assert r.get("signature_b64"), "missing Ed25519 leg"
    assert r.get("ml_dsa_signature_b64"), "missing ML-DSA-65 leg"
    assert r.get("slh_dsa_signature_b64"), "missing SLH-DSA leg"
    v = srv.tool_verify_receipt(r)
    assert v["ok"] is True


@pytest.mark.skipif(not _HAS_OAO, reason="openagentontology not available in this env")
def test_record_change_carries_hashes_not_cleartext():
    r = srv.tool_mint_receipt_for_record_change(
        record_id="p-1", object_type="Person", field="email",
        old_value="alice@old.example", new_value="alice@new.example",
        changed_by_agent="agent",
    )
    body = r["evidence"]["ontology"]
    assert body["old_value_hash"].startswith("sha256:")
    assert "alice@old.example" not in str(body)  # raw value not in clear


def test_record_change_rejects_missing_fields():
    r = srv.tool_mint_receipt_for_record_change(
        record_id="", object_type="Person", field="x",
        old_value="a", new_value="b", changed_by_agent="agent",
    )
    assert "error" in r


# ---- audit_my_agent_inventory --------------------------------------------------------
SAMPLE_INVENTORY = [
    {"server": "gmail", "tool": "send_email", "capability": "send"},
    {"server": "files", "tool": "delete_file", "capability": "delete"},
    {"server": "search", "tool": "web_search", "capability": "read"},
    {"server": "stripe", "tool": "charge_card", "capability": "pay"},
    {"server": "calendar", "tool": "create_event", "capability": "write"},
]


@pytest.mark.skipif(not _HAS_OAO, reason="openagentontology not available in this env")
def test_audit_ranks_by_worst_regret_critical_first():
    out = srv.tool_audit_my_agent_inventory(SAMPLE_INVENTORY)
    tiers = [r["tier"] for r in out["ranked"]]
    # delete + pay are CRITICAL -> at the top; read is LOW -> at the bottom
    assert tiers[0] == "CRITICAL" and tiers[-1] == "LOW"
    # both CRITICAL rows appear before any HIGH row
    first_high = next((i for i, t in enumerate(tiers) if t == "HIGH"), len(tiers))
    assert all(t == "CRITICAL" for t in tiers[:first_high])


def test_audit_carries_honest_scope_note():
    # honest-scope note must be on every response, not just in the docs
    out = srv.tool_audit_my_agent_inventory(SAMPLE_INVENTORY)
    assert "auto-discovery" in out["scope_note"].lower() or \
           "does not allow" in out["scope_note"].lower()


def test_audit_rejects_non_list():
    r = srv.tool_audit_my_agent_inventory("oops")  # type: ignore[arg-type]
    assert "error" in r


def test_audit_is_read_only_no_receipt():
    # design choice: an audit tool that scores OTHER tools' risk should not itself be a
    # side-effecting authority surface; receipt-minting is the caller's separate step.
    out = srv.tool_audit_my_agent_inventory(SAMPLE_INVENTORY)
    assert "receipt" not in out  # no side-effect
    assert "audit_manifest_for_receipt" in out  # caller can mint if it wants
    assert out["note"].startswith("this tool is read-only")


@pytest.mark.skipif(not _HAS_OAO, reason="openagentontology not available in this env")
def test_audit_manifest_can_be_minted_by_caller_and_tamper_caught():
    # the caller's responsibility -- the audit tool just hands back the manifest
    out = srv.tool_audit_my_agent_inventory(SAMPLE_INVENTORY)
    rec = srv.tool_mint_action_receipt(
        agent_id="auditor", operation="inventory_audit",
        target="caller-mcp-host", inputs=str(out["audit_manifest_for_receipt"]),
        decision="INVENTORY_AUDITED",
    )
    assert srv.tool_verify_receipt(rec)["ok"] is True
    bad = copy.deepcopy(rec)
    bad["evidence"]["ontology"]["inputs_hash"] = "sha256:" + "0" * 64
    assert srv.tool_verify_receipt(bad)["ok"] is False


# ---- mint_action_receipt + verify ----------------------------------------------------
@pytest.mark.skipif(not _HAS_OAO, reason="openagentontology not available in this env")
def test_action_receipt_mints_verifies_and_catches_tamper():
    r = srv.tool_mint_action_receipt(
        agent_id="deploy-agent", operation="deploy", target="prod/api",
        policy="EU AI Act Art 12", inputs="service=api;version=1.4.2",
    )
    assert srv.tool_verify_receipt(r)["ok"] is True
    bad = copy.deepcopy(r)
    bad["evidence"]["ontology"]["operation"] = "delete"
    assert srv.tool_verify_receipt(bad)["ok"] is False


# ---- the server factory wires all four tools -----------------------------------------
def test_build_server_wires_four_tools():
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("mcp SDK not installed in this env -- factory test skipped")
    s = srv.build_server()
    # FastMCP exposes a registry of tools; we don't pin to its private layout, just count.
    # Use the public list_tools() coroutine if present, else the internal _tools.
    tool_names = []
    if hasattr(s, "_tool_manager"):
        tool_names = list(getattr(s._tool_manager, "_tools", {}).keys())
    expected = {
        "mint_receipt_for_record_change", "audit_my_agent_inventory",
        "mint_action_receipt", "verify_receipt",
    }
    assert expected.issubset(set(tool_names)), f"missing tools; got {tool_names}"
