"""Trust Gate MCP Server -- hybrid-signed receipts for consequential agent actions.

A SELF-CONTAINED MCP server: it mints receipts locally via the open-source OpenAgentOntology
primitive (Ed25519 + ML-DSA-65). No hosted backend
dependency. A receipt's integrity verifies offline from the certificate alone; who signed it
needs the signer's kid pinned out of band.

Seven tools:

  gate_decision(action, resource, ...)  ALLOW / DENY / ESCALATE verdict + signed receipt
  mint_receipt_for_record_change(...)   tamper-evident per-change receipt for any CRM
  audit_my_agent_inventory(inventory)   worst-regret ranking of a CALLER-PROVIDED list (mints nothing)
  mint_action_receipt(...)              general-purpose consequential-action receipt
  verify_receipt(receipt, expected_kid) offline verify from the certificate alone
  check_egress(...)                     data-sensitivity classification of an outbound payload
  run_exit_drill()                      vendor-exit readiness check

No receipt. No trust.
"""

__version__ = "0.3.0"

from .server import build_server, main

# Lazy 'mcp' attribute -- builds the FastMCP server on first access so importing the
# package does not require the mcp dependency unless the caller actually runs a server.
_mcp = None
def __getattr__(name):
    global _mcp
    if name == "mcp":
        if _mcp is None:
            _mcp = build_server()
        return _mcp
    raise AttributeError(name)

__all__ = ["build_server", "main", "mcp", "__version__"]
