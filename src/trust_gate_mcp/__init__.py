"""Trust Gate MCP Server — Decision Trust for AI Agents.

Exposes Trust Gate capabilities as MCP tools that any AI agent can call
to gate decisions through OPA policies and mint Ed25519 cryptographic receipts.

No receipt. No trust.
"""

__version__ = "0.1.0"

from .server import main, mcp

__all__ = ["main", "mcp", "__version__"]
