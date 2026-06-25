"""Trust Gate API client — async HTTP interface to the Trust Gate backend.

Handles all communication with the hosted Trust Gate API including
policy evaluation, receipt minting, signature verification, and health checks.
"""

import logging
from typing import Any, Optional

import httpx

from .config import settings

logger = logging.getLogger("trust-gate-mcp.client")


class TrustGateError(Exception):
    """Error communicating with Trust Gate API.

    Attributes:
        status_code: HTTP status code (0 if no HTTP response).
        response_body: Truncated response body for debugging.
    """

    def __init__(self, message: str, status_code: int = 0, response_body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class TrustGateClient:
    """Async HTTP client for the Trust Gate API.

    Communicates with the hosted Trust Gate backend to evaluate OPA policies,
    mint Ed25519 TrustAtom receipts, and verify cryptographic signatures.

    Example:
        client = TrustGateClient(base_url="https://cwn-trust-gate.onrender.com")
        result = await client.gate_decision(
            action="DEPLOY", agent_id="my-agent", resource_id="prod-server-01"
        )
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.base_url = (base_url or settings.trust_gate_url).rstrip("/")
        self._api_key = api_key or settings.trust_gate_api_key
        self._timeout = timeout or settings.timeout

    def _headers(self) -> dict[str, str]:
        """Build request headers with Bearer auth if configured."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"trust-gate-mcp/{settings.trust_gate_url}",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def _request(
        self, method: str, path: str, json_body: Optional[dict] = None
    ) -> dict[str, Any]:
        """Send an HTTP request to the Trust Gate API.

        Args:
            method: HTTP method (GET, POST).
            path: API path (e.g., /api/mcp/gate).
            json_body: Optional JSON request body.

        Returns:
            Parsed JSON response as dict.

        Raises:
            TrustGateError: On HTTP errors, timeouts, or connection failures.
        """
        url = f"{self.base_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as http:
                response = await http.request(
                    method=method,
                    url=url,
                    json=json_body,
                    headers=self._headers(),
                )
                if response.status_code >= 400:
                    raise TrustGateError(
                        f"Trust Gate API {response.status_code}: {response.text[:200]}",
                        status_code=response.status_code,
                        response_body=response.text[:500],
                    )
                return response.json()
        except httpx.TimeoutException:
            raise TrustGateError(
                f"Trust Gate API timeout ({self._timeout}s) reaching {url}"
            )
        except httpx.ConnectError:
            raise TrustGateError(
                f"Cannot connect to Trust Gate at {self.base_url}. "
                "Verify TRUST_GATE_URL environment variable and network connectivity."
            )

    # ── Tool Methods ─────────────────────────────────────────────────

    async def gate_decision(
        self,
        action: str,
        agent_id: str,
        resource_id: str,
        tenant_id: str = "default",
        env: str = "SANDBOX",
        parent_decision_id: str = "",
        human_approved: bool = False,
    ) -> dict[str, Any]:
        """Submit a decision for OPA policy evaluation + TrustAtom receipt minting.

        Calls POST /api/mcp/gate on the Trust Gate backend.
        If the policy allows the action and it's high-risk, an Ed25519-signed
        TrustAtom receipt is minted and returned.
        """
        return await self._request(
            "POST",
            "/api/mcp/gate",
            {
                "tool_id": action,
                "tool_name": action,
                "agent_id": agent_id,
                "resource_id": resource_id,
                "tenant_id": tenant_id,
                "env": env,
                "parent_decision_id": parent_decision_id,
                "human_approved": human_approved,
            },
        )

    async def verify_receipt(
        self,
        evidence_hash: str,
        signature_b64: str,
        receipt_payload: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Verify a TrustAtom receipt's Ed25519 cryptographic signature.

        Calls POST /api/trustatom/verify on the Trust Gate backend.
        Optionally re-verifies the evidence hash against the original payload.
        """
        body: dict[str, Any] = {
            "evidence_hash": evidence_hash,
            "signature_b64": signature_b64,
        }
        if receipt_payload is not None:
            body["receipt_payload"] = receipt_payload
        return await self._request("POST", "/api/trustatom/verify", body)

    async def check_policy(
        self,
        action: str,
        agent_id: str,
        resource_id: str,
        tenant_id: str = "default",
        env: str = "SANDBOX",
    ) -> dict[str, Any]:
        """Dry-run a policy evaluation without minting a receipt.

        Calls POST /api/mcp/gate with dry_run=true. Returns the policy
        decision and risk score without creating any state.
        """
        return await self._request(
            "POST",
            "/api/mcp/gate",
            {
                "tool_id": action,
                "tool_name": action,
                "agent_id": agent_id,
                "resource_id": resource_id,
                "tenant_id": tenant_id,
                "env": env,
                "dry_run": True,
            },
        )

    async def health_check(self) -> dict[str, Any]:
        """Check Trust Gate backend health and connectivity.

        Calls GET /health on the Trust Gate backend.
        """
        return await self._request("GET", "/health")
