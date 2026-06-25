"""Trust Gate MCP Server -- post-quantum receipts for consequential agent actions.

v0.2.0 ARCHITECTURE CHANGE -- this release evolves Trust Gate MCP from a thin client
of the hosted cwn-trust-gate.onrender.com backend (v0.1.0) into a SELF-CONTAINED MCP
server that mints post-quantum receipts locally via the open-source OpenAgentOntology
primitive. No hosted backend dependency; receipts verify offline from the cert alone.

Four tools, all post-quantum by default (Ed25519 + ML-DSA-65 + SLH-DSA):

  mint_receipt_for_record_change(...)   tamper-evident per-change receipt for any CRM
  audit_my_agent_inventory(inventory)   worst-regret ranking of a CALLER-PROVIDED list
  mint_action_receipt(...)              general-purpose consequential-action receipt
  verify_receipt(receipt)               offline verify from the certificate alone

The v0.1.0 client.py + config.py modules are kept under this package for callers that
still need the hosted-backend integration path; they are not used by build_server().

No receipt. No trust.
"""

__version__ = "0.2.0"

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
