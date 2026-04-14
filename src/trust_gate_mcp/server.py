"""Trust Gate MCP Server — Decision Trust for AI Agents.

Exposes Trust Gate capabilities as MCP tools that any AI agent can call
to gate decisions through OPA policies and mint Ed25519 cryptographic receipts.

Usage:
    trust-gate-mcp                       # stdio transport (default)
    python -m trust_gate_mcp             # run as module
    uv run trust-gate-mcp               # via uv

Environment:
    TRUST_GATE_URL       API base URL (default: https://cwn-trust-gate.onrender.com)
    TRUST_GATE_API_KEY   Bearer token for authentication
    TRUST_GATE_TENANT    Default tenant ID (default: "default")
    TRUST_GATE_TIMEOUT   HTTP timeout in seconds (default: 30)
"""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .client import TrustGateClient
from .config import settings

logger = logging.getLogger("trust-gate-mcp")

mcp = FastMCP(
    "Trust Gate",
    instructions=(
        "Decision Trust for AI Agents. "
        "Gate any AI decision through OPA policies and mint "
        "Ed25519-signed cryptographic receipts. "
        "No receipt, no trust."
    ),
)

_client: Optional[TrustGateClient] = None


def _get_client() -> TrustGateClient:
    """Lazy-initialize the Trust Gate API client."""
    global _client
    if _client is None:
        _client = TrustGateClient()
    return _client


# ── Tools ────────────────────────────────────────────────────────────────────


@mcp.tool()
async def gate_decision(
    action: str,
    agent_id: str,
    resource_id: str,
    tenant_id: str = "default",
    env: str = "SANDBOX",
    parent_decision_id: str = "",
    human_approved: bool = False,
) -> str:
    """Gate an AI decision through OPA policy and mint a cryptographic receipt.

    Submit any consequential AI agent decision for policy evaluation.
    If the policy allows the action, Trust Gate mints an Ed25519-signed
    TrustAtom receipt — cryptographic proof the decision was evaluated,
    authorized, and recorded in an immutable graph.

    Call this BEFORE any action that modifies production state, deploys
    code, sends data externally, or makes commitments on behalf of users.

    Args:
        action: Action type being taken. Standard types:
                GRAPH_WRITE, GRAPH_READ, DEPLOY, EXPORT_INTEGRATION,
                CODE_GENERATION, MODIFY_POLICY, READ_EVIDENCE
        agent_id: Unique identifier of the agent making the decision
        resource_id: Identifier of the resource being acted upon
        tenant_id: Tenant context for multi-tenant deployments
        env: Environment context — SANDBOX, PRODUCTION, or STAGING
        parent_decision_id: ID of parent decision for provenance chains
        human_approved: Whether a human explicitly authorized this action

    Returns:
        JSON with: decision (allow/deny), risk_score, classification,
        and the signed TrustAtom receipt if approved and high-risk.
    """
    client = _get_client()
    try:
        result = await client.gate_decision(
            action=action,
            agent_id=agent_id,
            resource_id=resource_id,
            tenant_id=tenant_id,
            env=env,
            parent_decision_id=parent_decision_id,
            human_approved=human_approved,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error("gate_decision failed: %s", e)
        return json.dumps({
            "decision": {"allow": False, "deny_reasons": [str(e)]},
            "risk_score": 1.0,
            "receipt": None,
            "error": str(e),
        })


@mcp.tool()
async def verify_receipt(
    evidence_hash: str,
    signature: str,
    receipt_payload: str = "",
) -> str:
    """Verify a TrustAtom receipt's Ed25519 cryptographic signature.

    Confirms that a decision receipt is authentic, was signed by an
    authorized key, and has not been tampered with since creation.
    Verification is purely mathematical — no trust in the server required.

    Use this to independently verify any TrustAtom receipt before
    trusting its claims about what decision was made and when.

    Args:
        evidence_hash: SHA-256 hash of the original decision payload
                      (found in the receipt's evidence_hash field)
        signature: Base64-encoded Ed25519 signature from the receipt
                  (found in the receipt's signature_b64 field)
        receipt_payload: Optional JSON string of the original decision
                        payload to re-verify the evidence hash

    Returns:
        JSON with: valid (bool), reason, public_key_b64,
        and evidence_hash verification if receipt_payload provided.
    """
    client = _get_client()
    try:
        payload_dict = None
        if receipt_payload:
            payload_dict = json.loads(receipt_payload)
        result = await client.verify_receipt(
            evidence_hash=evidence_hash,
            signature_b64=signature,
            receipt_payload=payload_dict,
        )
        return json.dumps(result, indent=2)
    except json.JSONDecodeError as e:
        return json.dumps({
            "valid": False,
            "reason": f"Invalid receipt_payload JSON: {e}",
        })
    except Exception as e:
        logger.error("verify_receipt failed: %s", e)
        return json.dumps({
            "valid": False,
            "reason": f"Verification request failed: {e}",
        })


@mcp.tool()
async def check_policy(
    action: str,
    agent_id: str,
    resource_id: str,
    tenant_id: str = "default",
    env: str = "SANDBOX",
) -> str:
    """Dry-run a policy check without minting a receipt or recording state.

    Evaluate whether a proposed action would be allowed or denied by
    OPA policies, and what risk score it would receive. No receipt is
    minted, no decision is recorded, no state changes.

    Use this for:
    - Pre-flight checks before committing to an action
    - Testing policy configurations in sandbox
    - Understanding risk classification before proceeding
    - Building multi-step approval workflows

    Args:
        action: Action type to evaluate (same types as gate_decision)
        agent_id: Agent identifier for policy context
        resource_id: Resource identifier for policy context
        tenant_id: Tenant context
        env: Environment context — SANDBOX, PRODUCTION, or STAGING

    Returns:
        JSON with: allow (bool), risk_score, classification,
        policy_version, and evaluation_ms.
    """
    client = _get_client()
    try:
        result = await client.check_policy(
            action=action,
            agent_id=agent_id,
            resource_id=resource_id,
            tenant_id=tenant_id,
            env=env,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error("check_policy failed: %s", e)
        return json.dumps({
            "allowed": False,
            "reason": f"Policy evaluation failed: {e}",
            "risk_score": 1.0,
        })


@mcp.tool()
async def health() -> str:
    """Check Trust Gate service health and connectivity.

    Verifies the MCP server can reach the Trust Gate backend API.
    Returns service status, version, and deployment information.
    Call this first to confirm connectivity before gating decisions.

    Returns:
        JSON with: status, version, and environment details.
    """
    client = _get_client()
    try:
        result = await client.health_check()
        result["mcp_server_version"] = "0.1.0"
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error("health check failed: %s", e)
        return json.dumps({
            "status": "unreachable",
            "error": str(e),
            "trust_gate_url": settings.trust_gate_url,
            "mcp_server_version": "0.1.0",
        })


# ── Entry Point ──────────────────────────────────────────────────────────────


def main():
    """Run the Trust Gate MCP server with stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
