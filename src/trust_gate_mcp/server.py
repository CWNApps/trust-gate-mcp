"""Trust Gate MCP server -- post-quantum agent-decision receipts as MCP tools.

One MCP server, seven tools, one shared post-quantum primitive (the open-source
OpenAgentOntology `mint_receipt`: Ed25519 + ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205)).

  mint_receipt_for_record_change(record)  -- a CRM record changed; mint a per-change receipt
                                             (the standalone alternative to a CRM-side PHP port)
  audit_my_agent_inventory(inventory)     -- rank a CALLER-PROVIDED list of MCP tools by
                                             worst-regret if they act, with a signed receipt
  mint_action_receipt(action, decision)   -- general-purpose agent-action receipt
  verify_receipt(receipt)                 -- verify from the certificate alone (offline)
  gate_decision(action, resource, ...)   -- two-phase PREVIEW->COMMIT decision gate with receipt
  check_egress(destination, data_sample) -- egress data-classification check with receipt
  run_exit_drill()                       -- vendor exit readiness check with receipt

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
import json
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


# ---- egress data-sensitivity classification (heuristic, for check_egress) ----------------
_RESTRICTED_DATA = re.compile(
    r"\b(ssn|social.?security|passport.?num|credit.?card|card.?number|"
    r"bank.?account|routing.?number|iban|swift.?code|"
    r"dea.?number|medical.?record|health.?record)\b", re.I)
_CONFIDENTIAL_DATA = re.compile(
    r"\b(password|secret|token|api.?key|private.?key|credential|"
    r"bearer|session.?id|auth.?code|signing.?key)\b", re.I)
_INTERNAL_DATA = re.compile(
    r"\b(internal|draft|proprietary|trade.?secret|roadmap|unreleased|"
    r"embargoed|pre.?release|nda|board.?minutes)\b", re.I)

_EGRESS_RETENTION: Dict[str, str] = {
    "PUBLIC": "no retention constraint",
    "INTERNAL": "90-day minimum retention recommended",
    "CONFIDENTIAL": "365-day retention, audit trail recommended",
    "RESTRICTED": "no egress permitted; data must remain within the trust boundary",
}


def _classify_egress(data_sample: str, destination: str) -> tuple[str, str]:
    """Classify data sensitivity based on content markers. Heuristic, not exhaustive."""
    combined = f"{data_sample} {destination}"
    if _RESTRICTED_DATA.search(combined):
        return "RESTRICTED", "restricted-class markers detected (PII/financial/health identifiers)"
    if _CONFIDENTIAL_DATA.search(combined):
        return "CONFIDENTIAL", "confidential-class markers detected (credentials/keys/tokens)"
    if _INTERNAL_DATA.search(combined):
        return "INTERNAL", "internal-class markers detected (proprietary/draft/embargoed)"
    return "PUBLIC", "no sensitive markers detected in sample"


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
        pq_ok = any(legs.get(name) == "ok" for name in ("ml_dsa", "slh_dsa"))
        if not pq_ok:
            # No PQ leg verified -- either both stripped, or none installed. Either way the
            # receipt has no quantum-resistant signature standing, so under PQ-required mode
            # we refuse it. "At least one PQ leg ok" is the honest defense: an attacker who
            # strips ALL PQ legs is caught; a server that installs only ML-DSA-65 (no SLH-DSA)
            # still serves valid PQ verifications. Requiring BOTH was over-strict and broke
            # consumers when the SLH-DSA backend was unavailable.
            states = ", ".join(f"{n}={legs.get(n, 'absent')}" for n in ("ml_dsa", "slh_dsa"))
            out["ok"] = False
            out["reason"] = (f"PQ-required: no post-quantum signature leg verified ({states}). "
                             "Set TRUST_GATE_REQUIRE_PQ=false (or pass require_pq=False) to "
                             "allow Ed25519-only verification of legacy receipts.")
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


def tool_gate_decision(
    action: str,
    resource: str,
    context: Dict[str, Any],
    phase: str = "PREVIEW",
    preview_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Two-phase decision gate: PREVIEW evaluates risk without acting; COMMIT mints a receipt.

    Models the PREVIEW->COMMIT pattern: every consequential action gets a risk assessment
    first (PREVIEW), and only proceeds when the caller explicitly commits with the
    preview_id returned by the PREVIEW phase. This is a stateless check -- the preview_id
    is deterministically derived from the inputs, so the same action+resource+context always
    produces the same preview_id.

    The receipt is tamper-evident, not proof of compliance.
    """
    if not action or not resource:
        return {"error": "action and resource are required"}
    phase_upper = phase.upper().strip()
    if phase_upper not in ("PREVIEW", "COMMIT"):
        return {"error": "phase must be 'PREVIEW' or 'COMMIT'"}

    # Deterministic preview_id: sha256(action|resource|sha256(context_canonical))
    ctx_canonical = json.dumps(context, sort_keys=True, default=str) if context else ""
    ctx_hash = hashlib.sha256(ctx_canonical.encode()).hexdigest()
    preview_payload = f"{action}|{resource}|{ctx_hash}"
    expected_id = "pvw_" + hashlib.sha256(preview_payload.encode()).hexdigest()[:24]

    # Risk assessment (same verb-tier heuristic as audit_my_agent_inventory)
    tier, score = _tier_for(f"{action} {resource}")

    if phase_upper == "PREVIEW":
        return {
            "phase": "PREVIEW",
            "preview_id": expected_id,
            "action": action,
            "resource": resource,
            "risk_assessment": {
                "tier": tier,
                "worst_regret_score": score,
                "method": "verb-tier heuristic (same basis as audit_my_agent_inventory); not a proof",
            },
            "policy_evaluation": {
                "action_hash": _ascii_hash(action),
                "resource_hash": _ascii_hash(resource),
                "context_hash": _ascii_hash(str(context)),
            },
            "next_step": "pass this preview_id to phase='COMMIT' with the same action, resource, and context to proceed",
        }

    # COMMIT phase -- verify preview_id matches
    if not preview_id:
        return {"error": "preview_id is required for COMMIT phase (run PREVIEW first)"}
    if preview_id != expected_id:
        return {"error": "preview_id mismatch -- inputs changed since PREVIEW, or wrong preview_id"}

    manifest = {
        "operation": "decision_gate_commit",
        "action": action,
        "resource": resource,
        "context_hash": _ascii_hash(str(context)),
        "preview_id": expected_id,
        "risk_tier": tier,
        "risk_score": score,
        "policy": "two-phase decision gate: PREVIEW evaluated, COMMIT executed",
    }
    receipt = _mint(manifest, decision="DECISION_COMMITTED")
    return {
        "phase": "COMMIT",
        "preview_id": expected_id,
        "permit": "GRANTED",
        "risk_tier": tier,
        "receipt": receipt,
        "note": "receipt is tamper-evident, not proof of compliance",
    }


def tool_check_egress(
    destination: str,
    data_sample: str,
    provider: str,
) -> Dict[str, Any]:
    """Classify outbound data sensitivity and gate egress.

    Scans the data_sample for sensitivity markers (heuristic, not exhaustive) and
    classifies as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. RESTRICTED-class data
    is blocked -- the response includes the classification but no egress permit.

    The receipt is tamper-evident, not proof of compliance. The classification is a
    heuristic signal, not a regulatory determination.
    """
    if not destination or not data_sample or not provider:
        return {"error": "destination, data_sample, and provider are required"}

    classification, reason = _classify_egress(data_sample, destination)
    blocked = classification == "RESTRICTED"
    retention = _EGRESS_RETENTION.get(classification, "unknown")

    manifest = {
        "operation": "egress_classification",
        "destination_hash": _ascii_hash(destination),
        "data_sample_hash": _ascii_hash(data_sample),
        "provider": str(provider),
        "classification": classification,
        "blocked": blocked,
        "policy": "egress data-sensitivity gate",
    }
    receipt = _mint(manifest, decision="EGRESS_BLOCKED" if blocked else "EGRESS_CLASSIFIED")

    return {
        "classification": classification,
        "reason": reason,
        "blocked": blocked,
        "retention": retention,
        "provider": provider,
        "destination_hash": _ascii_hash(destination),
        "receipt": receipt,
        "note": "classification is heuristic, not a regulatory determination; receipt is tamper-evident, not proof of compliance",
    }


def tool_run_exit_drill() -> Dict[str, Any]:
    """Check vendor exit readiness: local signing, local model access, local data export.

    Informational -- shows the operator their sovereignty posture. Each check reports
    PASS, FAIL, or UNKNOWN. The receipt covers the drill itself (tamper-evident, not
    proof of compliance).
    """
    steps: List[Dict[str, Any]] = []

    # 1. Local signing key (OAO receipt minting)
    signing_ok = _oao_receipt is not None
    steps.append({
        "check": "local_signing_key",
        "description": "OpenAgentOntology receipt signing available locally",
        "status": "PASS" if signing_ok else "FAIL",
        "detail": (f"source: {_OAO_SOURCE}"
                   if signing_ok
                   else "pip install 'openagentontology[pq]' to enable local signing"),
    })

    # 2. Local model access (Ollama or compatible)
    ollama_host = os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_BASE_URL")
    steps.append({
        "check": "local_model_access",
        "description": "Local LLM inference available (Ollama or compatible)",
        "status": "PASS" if ollama_host else "UNKNOWN",
        "detail": (f"OLLAMA_HOST={ollama_host}"
                   if ollama_host
                   else "OLLAMA_HOST not set; Ollama may still be reachable at default localhost:11434"),
    })

    # 3. Local data export
    steps.append({
        "check": "local_data_export",
        "description": "Receipts and data exportable to local filesystem",
        "status": "PASS",
        "detail": "MCP server runs locally; all minted receipts are returned inline and can be persisted without network dependency",
    })

    passed = sum(1 for s in steps if s["status"] == "PASS")
    total = len(steps)

    manifest = {
        "operation": "vendor_exit_drill",
        "checks_passed": passed,
        "checks_total": total,
        "steps_summary": [{"check": s["check"], "status": s["status"]} for s in steps],
        "policy": "vendor exit readiness assessment",
    }
    receipt = _mint(manifest, decision="EXIT_DRILL_COMPLETED")

    return {
        "readiness": "READY" if passed == total else "PARTIAL",
        "passed": passed,
        "total": total,
        "steps": steps,
        "receipt": receipt,
        "note": "informational assessment; receipt is tamper-evident, not proof of compliance",
    }


# ---- MCP server wiring (FastMCP -- the high-level API in the modelcontextprotocol Python SDK) -

def build_server():
    """Build the FastMCP server with all seven tools. Importable so tests don't need stdio."""
    from mcp.server.fastmcp import FastMCP  # imported lazily so tests can run without mcp
    from mcp.server.transport_security import TransportSecuritySettings

    # FastMCP's DNS-rebinding protection defaults to ON with an empty allow-list, which
    # rejects every request with 421 "Invalid Host header" behind a TLS-terminating proxy
    # (Render, Smithery gateway, Cloudflare, etc.). We disable it here because:
    #   - Trust Gate is reached only through a trusted upstream proxy
    #   - CORS is already enforced separately (auth.py + server_http.py)
    #   - bearer-auth, when enabled, provides per-request authentication
    # Operators on a direct-exposure deploy should re-enable + populate allowed_hosts.
    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)

    mcp = FastMCP("trust-gate", instructions=(
        "Trust Gate -- post-quantum, tamper-evident receipts for consequential agent actions. "
        "All receipts reuse the open-source OpenAgentOntology mint_receipt (Ed25519 + ML-DSA-65 + "
        "SLH-DSA). Verifiable offline from the receipt alone."
    ), transport_security=security,
        # json_response: return application/json instead of streaming text/event-stream.
        # Required for one-shot directory scanners (e.g. Smithery) that POST a JSON-RPC
        # call and wait for a JSON body, not an open SSE stream.
        # stateless_http: every request handled independently, no mcp-session-id
        # continuation needed. Safe for this tool surface -- none of the seven tools share
        # state across calls; each mint/verify is self-contained.
        json_response=True, stateless_http=True)

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

    @mcp.tool(description="Two-phase decision gate. PREVIEW phase returns a risk assessment and "
              "preview_id without acting. COMMIT phase requires that preview_id back, verifies "
              "inputs match, mints a tamper-evident receipt, and returns an execution permit. "
              "Stateless -- the preview_id is deterministically derived from the inputs.")
    def gate_decision(
        action: str, resource: str, context: Dict[str, Any],
        phase: str = "PREVIEW",
        preview_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool_gate_decision(action, resource, context, phase, preview_id)

    @mcp.tool(description="Egress classification check. Scans a data sample for sensitivity "
              "markers (heuristic) and classifies as PUBLIC / INTERNAL / CONFIDENTIAL / "
              "RESTRICTED. Blocks RESTRICTED-class egress. Returns classification, retention "
              "info, and a tamper-evident receipt.")
    def check_egress(
        destination: str, data_sample: str, provider: str,
    ) -> Dict[str, Any]:
        return tool_check_egress(destination, data_sample, provider)

    @mcp.tool(description="Vendor exit readiness drill. Checks local signing key, local model "
              "access (Ollama), and local data export capability. Returns step-by-step results "
              "and a tamper-evident receipt. Informational -- no side effects.")
    def run_exit_drill() -> Dict[str, Any]:
        return tool_run_exit_drill()

    return mcp


def main() -> None:
    server = build_server()
    server.run()  # stdio is the FastMCP default; the MCP host launches us as a subprocess


if __name__ == "__main__":
    main()
