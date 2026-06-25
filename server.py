"""Trust Gate MCP server -- post-quantum agent-decision receipts as MCP tools.

One MCP server, four tools, one shared post-quantum primitive (the open-source
OpenAgentOntology `mint_receipt`: Ed25519 + ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205)).

  mint_receipt_for_record_change(record)  -- a CRM record changed; mint a per-change receipt
                                             (the standalone alternative to a CRM-side PHP port)
  audit_my_agent_inventory(inventory)     -- rank a CALLER-PROVIDED list of MCP tools by
                                             worst-regret if they act, with a signed receipt
  mint_action_receipt(action, decision)   -- general-purpose agent-action receipt
  verify_receipt(receipt)                 -- verify from the certificate alone (offline)

Honesty constraints (encoded, not optional):

  * audit_my_agent_inventory CANNOT auto-discover other MCP servers. The MCP protocol gives
    one server no view of the host's other installed servers. The caller must pass the list
    in. The tool's docstring + every response says so explicitly. (See AGENTS.md gate G3.)

  * The receipts are "tamper-evident", not "proof of compliance" or "admissible". Wording is
    deliberate; do not edit it to be marketing-flavoured. (See AGENTS.md gate G4.)

  * All crypto is the merged OAO `mint_receipt`. This server adds no signing code of its own,
    so every receipt inherits the post-quantum legs by default (gate G1).

Run:
    pip install mcp "openagentontology[pq]"
    python server.py                 # stdio (the standard MCP transport)
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from typing import Any, Dict, List, Optional

# ---- the receipt primitive (one source of truth, post-quantum by default) ------------
# Tries the installed package first; falls back to the in-repo OAO checkout so the server
# is testable from the repo without an editable install. If both fail the tools surface a
# clear, structured error rather than silently returning unsigned receipts.
try:
    from openagentontology import receipt as _oao_receipt  # type: ignore
    _OAO_SOURCE = "installed"
except ImportError:
    import pathlib
    _here = pathlib.Path(__file__).resolve()
    # walk up to the "Dev" repo root; trust_gate_mcp/ -> distribution -> scaffolding ->
    # 2026-06-24_goal_aoa_gtm -> gtm -> Dev (parents[5]).
    _dev = _here.parents[5]
    _oao_path = _dev / "oss" / "openagentontology"
    if _oao_path.exists() and str(_oao_path) not in sys.path:
        sys.path.insert(0, str(_oao_path))
    try:
        from openagentontology import receipt as _oao_receipt  # type: ignore
        _OAO_SOURCE = f"repo:{_oao_path}"
    except ImportError:
        _oao_receipt = None  # type: ignore[assignment]
        _OAO_SOURCE = "missing"


# ---- worst-regret scoring (sourced; for audit_my_agent_inventory) --------------------
# OWASP Agentic AI Top 10 names "Excessive Agency" as the through-line: a tool that can
# act on the world in side-effecting ways is worst-regret if it acts unexpectedly. We tier
# by the verbs the tool/server's NAME (and declared capabilities) carry. This is a
# heuristic ranking, not a proof; the tool's output says so.
_TIER_CRITICAL = re.compile(
    r"\b(pay|payment|wire|transfer|remit|disburse|refund|withdraw|"
    r"delete|drop|purge|wipe|destroy|truncate|"
    r"deploy|release|rollout|provision|migrate|reconfigure|"
    r"grant|revoke|escalate|elevate|impersonate)\b", re.I)
_TIER_HIGH = re.compile(
    r"\b(send|email|post|message|outreach|publish|"
    r"export|egress|exfil|upload|share|"
    r"approve|deny|reject|decline|cancel|adverse|terminate|suspend)\b", re.I)
_TIER_MEDIUM = re.compile(
    r"\b(write|create|update|edit|modify|change|insert|append|"
    r"book|schedule|reserve|charge)\b", re.I)
_TIER_LOW = re.compile(
    r"\b(read|get|list|search|query|find|show|view|inspect|describe)\b", re.I)


def _tier_for(label: str) -> tuple[str, int]:
    """Return (tier, score) for a tool/server label. Worst-regret = highest score."""
    if _TIER_CRITICAL.search(label):
        return "CRITICAL", 90
    if _TIER_HIGH.search(label):
        return "HIGH", 70
    if _TIER_MEDIUM.search(label):
        return "MEDIUM", 40
    if _TIER_LOW.search(label):
        return "LOW", 10
    return "UNKNOWN", 50  # absent signal -> assume the middle, surface it


def _ascii_hash(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def _kid(receipt: Dict[str, Any]) -> str:
    """Key identifier = sha256(verify_pubkey_b64)[:32] (128 bits). Lets a verifier comparing
    two receipts answer 'signed by the same notary?' offline, without trusting any registry.
    128 bits gives adversarial collision resistance well past the lifetime of any one key;
    a shorter prefix would not. Empty string for unsigned receipts (no public key)."""
    pub = receipt.get("verify_pubkey_b64", "")
    if not pub:
        return ""
    return hashlib.sha256(pub.encode("ascii")).hexdigest()[:32]


def _mint(manifest: Dict[str, Any], decision: str) -> Dict[str, Any]:
    """Reuse OAO's mint_receipt for every receipt -- one signing path, PQ by default."""
    if _oao_receipt is None:
        return {
            "error": "openagentontology_unavailable",
            "remedy": "pip install \"openagentontology[pq]\"",
            "decision": decision,
            "manifest": manifest,
        }
    receipt = _oao_receipt.mint_receipt(manifest, decision=decision)
    # Add the kid for key-rotation continuity. Cost: one sha256 per mint. Inherited by
    # every tool because they all funnel through _mint.
    receipt["kid"] = _kid(receipt)
    return receipt


def _require_pq_default() -> bool:
    """Env switch (default ON). Accepts BOTH `TRUST_GATE_REQUIRE_PQ` and `OAO_REQUIRE_PQ`
    so one env var configures every CWN distribution artifact (this server, the SalesGPT
    and OpenOutreach shims, the OAO repo). `TRUST_GATE_REQUIRE_PQ` wins when both are
    set. Defends against signature-stripping where an attacker removes the PQ legs to
    leave only Ed25519 (which loses ~half its security under a future quantum adversary).
    When ON, verify FAILS if either ML-DSA-65 or SLH-DSA is missing/unverifiable; the
    Ed25519-only path is still available for callers that pass require_pq=False explicitly."""
    raw = (os.environ.get("TRUST_GATE_REQUIRE_PQ")
           or os.environ.get("OAO_REQUIRE_PQ")
           or "true").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _verify(receipt: Dict[str, Any], *, require_pq: Optional[bool] = None) -> Dict[str, Any]:
    if _oao_receipt is None:
        return {"ok": False, "reason": "openagentontology not installed (cannot verify)"}
    out = _oao_receipt.verify_receipt(receipt)
    # PQ-required gate -- only meaningful for SIGNED receipts; unsigned receipts already
    # report ok=True with a different reason and shouldn't be downgraded by this check.
    must = _require_pq_default() if require_pq is None else bool(require_pq)
    if must and out.get("ok") and out.get("signed"):
        legs = out.get("legs", {})
        missing = [name for name in ("ml_dsa", "slh_dsa") if legs.get(name) != "ok"]
        if missing:
            out["ok"] = False
            out["reason"] = ("PQ-required: " + ", ".join(missing) + " not verified ("
                             + ", ".join(f"{m}={legs.get(m, 'absent')}" for m in missing) + "). "
                             "Set OAO_REQUIRE_PQ=false or pass require_pq=False to allow "
                             "Ed25519-only verification.")
    return out


# ---- tool implementations (pure, unit-testable) --------------------------------------

def tool_mint_receipt_for_record_change(
    record_id: str,
    object_type: str,
    field: str,
    old_value: str,
    new_value: str,
    changed_by_agent: str,
    tenant: Optional[str] = None,
    policy: str = "per-decision CRM change evidence",
) -> Dict[str, Any]:
    """Mint a post-quantum receipt for one CRM record change.

    The full new/old values are carried as SHA-256 hashes (tamper-evidence, not redaction;
    low-entropy values are guessable). Designed for any CRM with an MCP integration -- the
    open-core Relaticle, a hosted CRM via its own MCP, or a custom one. The receipt is
    verifiable offline from its certificate alone.
    """
    if not record_id or not object_type or not field:
        return {"error": "record_id, object_type, and field are required"}
    manifest = {
        "operation": "crm_record_change",
        "record_id": str(record_id),
        "object_type": str(object_type),       # Person / Company / Opportunity / ...
        "field": str(field),
        "old_value_hash": _ascii_hash(str(old_value)),
        "new_value_hash": _ascii_hash(str(new_value)),
        "changed_by_agent": str(changed_by_agent),
        "tenant": str(tenant) if tenant else None,
        "policy": policy,
    }
    return _mint(manifest, decision="CRM_RECORD_CHANGED")


def tool_audit_my_agent_inventory(
    inventory: List[Dict[str, Any]],
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Rank a CALLER-PROVIDED list of MCP tools by worst-regret if they act.

    HONEST SCOPE (in every response): the MCP protocol does NOT let one server introspect
    the host's other installed servers. So this tool cannot auto-discover the caller's
    inventory; the caller must pass it in, e.g.:
        [{"server": "gmail", "tool": "send_email", "capability": "send"}, ...]

    Each row is tiered (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN) using side-effecting verbs
    in its label, anchored to OWASP Agentic Threats T2 (Tool Misuse) + T3 (Privilege
    Compromise) and LLM Top 10 LLM06 (Excessive Agency). This is a heuristic ranking, not a
    proof; verb inference from a tool NAME can misfire (e.g. "delete_label" vs "delete_user").

    READ-ONLY by design: this tool returns the ranking only and does NOT mint a receipt.
    Receipt-minting is a separate, side-effecting action -- the caller, if it wants the
    audit recorded, calls `mint_action_receipt` with the returned manifest hash. Keeping
    the auditor read-only avoids it being a side-effecting authority surface itself.
    """
    if not isinstance(inventory, list):
        return {"error": "inventory must be a list of {server, tool, capability?} dicts"}
    ranked: List[Dict[str, Any]] = []
    for row in inventory:
        if not isinstance(row, dict):
            continue
        label_bits = [str(row.get(k, "")) for k in ("server", "tool", "capability")]
        label = " ".join(b for b in label_bits if b)
        tier, score = _tier_for(label)
        ranked.append({
            "server": row.get("server"),
            "tool": row.get("tool"),
            "capability": row.get("capability"),
            "tier": tier,
            "worst_regret_score": score,
        })
    ranked.sort(key=lambda r: r["worst_regret_score"], reverse=True)

    # the deterministic manifest the caller can hand to mint_action_receipt
    audit_manifest = {
        "operation": "agent_inventory_audit",
        "scope_note": "input-driven: the MCP protocol does not allow auto-discovery of other servers; the caller supplied the inventory",
        "owasp_anchor": "Agentic Threats T2 (Tool Misuse), T3 (Privilege Compromise); LLM Top 10 LLM06 (Excessive Agency)",
        "ranking_method": "verb-tier heuristic (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN); not a proof",
        "row_count": len(ranked),
        "ranked": ranked,
        "notes": notes or "",
    }
    return {
        "scope_note": audit_manifest["scope_note"],
        "owasp_anchor": audit_manifest["owasp_anchor"],
        "ranking_method": audit_manifest["ranking_method"],
        "ranked": ranked,
        "audit_manifest_for_receipt": audit_manifest,
        "note": "this tool is read-only and does not mint a receipt; pass audit_manifest_for_receipt to mint_action_receipt if you want the audit recorded",
    }


def tool_mint_action_receipt(
    agent_id: str,
    operation: str,
    target: str,
    policy: str = "agent action evidence",
    inputs: Optional[str] = None,
    decision: str = "ACTION_GOVERNED",
) -> Dict[str, Any]:
    """Mint a post-quantum receipt for an arbitrary consequential agent action."""
    if not agent_id or not operation or not target:
        return {"error": "agent_id, operation, and target are required"}
    manifest = {
        "operation": str(operation),
        "agent_id": str(agent_id),
        "target": str(target),
        "policy": str(policy),
        "inputs_hash": _ascii_hash(inputs or ""),
    }
    return _mint(manifest, decision=decision)


def tool_verify_receipt(receipt: Dict[str, Any],
                        require_pq: Optional[bool] = None) -> Dict[str, Any]:
    """Verify a Trust Gate receipt from the certificate alone (no DB, no network).

    require_pq  None (default) -> obey the OAO_REQUIRE_PQ env switch (default ON).
                True            -> FAIL if ML-DSA-65 or SLH-DSA is missing/unverified.
                                   Defends against PQ-leg-stripping downgrade attacks.
                False           -> Ed25519-only verification is allowed (legacy mode).
    """
    if not isinstance(receipt, dict):
        return {"ok": False, "reason": "receipt must be a JSON object"}
    return _verify(receipt, require_pq=require_pq)


# ---- MCP server wiring (FastMCP -- the high-level API in the modelcontextprotocol Python SDK) -

def build_server():
    """Build the FastMCP server with all four tools. Importable so tests don't need stdio."""
    from mcp.server.fastmcp import FastMCP  # imported lazily so tests can run without mcp
    mcp = FastMCP("trust-gate", instructions=(
        "Trust Gate -- post-quantum, tamper-evident receipts for consequential agent actions. "
        "All receipts reuse the open-source OpenAgentOntology mint_receipt (Ed25519 + ML-DSA-65 + "
        "SLH-DSA). Verifiable offline from the receipt alone."
    ))

    @mcp.tool(description="Mint a post-quantum receipt for one CRM record change. Old/new values "
              "are carried as SHA-256 hashes. Works with any CRM (Relaticle, hosted CRMs, custom).")
    def mint_receipt_for_record_change(
        record_id: str, object_type: str, field: str,
        old_value: str, new_value: str, changed_by_agent: str,
        tenant: Optional[str] = None,
        policy: str = "per-decision CRM change evidence",
    ) -> Dict[str, Any]:
        return tool_mint_receipt_for_record_change(
            record_id, object_type, field, old_value, new_value,
            changed_by_agent, tenant, policy)

    @mcp.tool(description="Rank a CALLER-PROVIDED list of MCP tools by worst-regret if they act, "
              "with a signed receipt. Cannot auto-discover the inventory -- MCP does not allow that; "
              "the caller must pass it in.")
    def audit_my_agent_inventory(
        inventory: List[Dict[str, Any]],
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_audit_my_agent_inventory(inventory, notes)

    @mcp.tool(description="Mint a post-quantum receipt for an arbitrary consequential agent action.")
    def mint_action_receipt(
        agent_id: str, operation: str, target: str,
        policy: str = "agent action evidence",
        inputs: Optional[str] = None,
        decision: str = "ACTION_GOVERNED",
    ) -> Dict[str, Any]:
        return tool_mint_action_receipt(agent_id, operation, target, policy, inputs, decision)

    @mcp.tool(description="Verify a Trust Gate receipt from the certificate alone (offline). "
              "require_pq=True (default via OAO_REQUIRE_PQ) FAILS if the ML-DSA-65 or SLH-DSA "
              "legs are missing -- defends against signature-stripping downgrade attacks.")
    def verify_receipt(receipt: Dict[str, Any],
                       require_pq: Optional[bool] = None) -> Dict[str, Any]:
        return tool_verify_receipt(receipt, require_pq)

    return mcp


def main() -> None:
    server = build_server()
    server.run()  # stdio is the FastMCP default; the MCP host launches us as a subprocess


if __name__ == "__main__":
    main()
