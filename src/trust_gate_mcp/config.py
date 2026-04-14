"""Configuration for Trust Gate MCP Server.

All settings loaded from environment variables with sensible defaults.
Set TRUST_GATE_API_KEY to authenticate with the Trust Gate backend.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Trust Gate MCP server configuration.

    Attributes:
        trust_gate_url: Base URL of the Trust Gate API backend.
        trust_gate_api_key: Bearer token for API authentication.
        signing_key_path: Path to local Ed25519 signing key (optional).
        default_tenant: Default tenant ID for multi-tenant deployments.
        timeout: HTTP request timeout in seconds.
    """

    trust_gate_url: str
    trust_gate_api_key: str
    signing_key_path: str
    default_tenant: str
    timeout: int

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables.

        Environment Variables:
            TRUST_GATE_URL:     API base URL (default: https://cwn-trust-gate.onrender.com)
            TRUST_GATE_API_KEY: Bearer token for authentication (required for gated ops)
            TRUST_GATE_KEY_PATH: Local Ed25519 key path (optional, for local signing)
            TRUST_GATE_TENANT:  Default tenant ID (default: "default")
            TRUST_GATE_TIMEOUT: HTTP timeout in seconds (default: 30)
        """
        return cls(
            trust_gate_url=os.getenv(
                "TRUST_GATE_URL", "https://cwn-trust-gate.onrender.com"
            ),
            trust_gate_api_key=os.getenv("TRUST_GATE_API_KEY", ""),
            signing_key_path=os.getenv("TRUST_GATE_KEY_PATH", ""),
            default_tenant=os.getenv("TRUST_GATE_TENANT", "default"),
            timeout=int(os.getenv("TRUST_GATE_TIMEOUT", "30")),
        )


# Module-level singleton — loaded once at import time
settings = Settings.from_env()
