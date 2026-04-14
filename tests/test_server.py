"""Tests for Trust Gate MCP Server.

Tests cover: configuration, client request construction, server tool
responses, and error handling. All HTTP calls are mocked.

Run: cd mcp/trust-gate-server && pip install -e ".[dev]" && pytest
"""

import json
import os
from unittest.mock import AsyncMock, patch

import pytest


# ── Configuration Tests ──────────────────────────────────────────────────────


class TestConfig:
    """Test Settings loads correctly from environment."""

    def test_default_settings(self):
        """Settings use sensible defaults when no env vars set."""
        with patch.dict(os.environ, {}, clear=True):
            from trust_gate_mcp.config import Settings

            s = Settings.from_env()
            assert s.trust_gate_url == "https://cwn-trust-gate.onrender.com"
            assert s.trust_gate_api_key == ""
            assert s.default_tenant == "default"
            assert s.timeout == 30

    def test_custom_settings_from_env(self):
        """Settings load from environment variables."""
        env = {
            "TRUST_GATE_URL": "http://localhost:8080",
            "TRUST_GATE_API_KEY": "test-key-abc123",
            "TRUST_GATE_TENANT": "acme-corp",
            "TRUST_GATE_TIMEOUT": "60",
            "TRUST_GATE_KEY_PATH": "/keys/ed25519.key",
        }
        with patch.dict(os.environ, env, clear=True):
            from trust_gate_mcp.config import Settings

            s = Settings.from_env()
            assert s.trust_gate_url == "http://localhost:8080"
            assert s.trust_gate_api_key == "test-key-abc123"
            assert s.default_tenant == "acme-corp"
            assert s.timeout == 60
            assert s.signing_key_path == "/keys/ed25519.key"

    def test_settings_are_frozen(self):
        """Settings dataclass is immutable after creation."""
        with patch.dict(os.environ, {}, clear=True):
            from trust_gate_mcp.config import Settings

            s = Settings.from_env()
            with pytest.raises(AttributeError):
                s.trust_gate_url = "http://evil.com"


# ── Client Tests ─────────────────────────────────────────────────────────────


class TestClientHeaders:
    """Test TrustGateClient header construction."""

    def test_headers_include_auth_when_key_set(self):
        from trust_gate_mcp.client import TrustGateClient

        client = TrustGateClient(
            base_url="http://test:8080", api_key="bearer-token-xyz"
        )
        headers = client._headers()
        assert headers["Authorization"] == "Bearer bearer-token-xyz"
        assert headers["Content-Type"] == "application/json"
        assert "User-Agent" in headers

    def test_headers_omit_auth_when_no_key(self):
        from trust_gate_mcp.client import TrustGateClient

        client = TrustGateClient(base_url="http://test:8080", api_key="")
        headers = client._headers()
        assert "Authorization" not in headers

    def test_base_url_strips_trailing_slash(self):
        from trust_gate_mcp.client import TrustGateClient

        client = TrustGateClient(base_url="http://test:8080/")
        assert client.base_url == "http://test:8080"


class TestClientMethods:
    """Test TrustGateClient API methods using mocked _request."""

    @pytest.fixture
    def client(self):
        from trust_gate_mcp.client import TrustGateClient

        return TrustGateClient(
            base_url="http://test:8080", api_key="test-key", timeout=5
        )

    @pytest.mark.asyncio
    async def test_gate_decision_calls_correct_endpoint(self, client):
        mock_response = {
            "decision": {"allow": True, "risk_score": 0.3},
            "tool_id": "DEPLOY",
        }
        with patch.object(
            client, "_request", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.gate_decision(
                action="DEPLOY", agent_id="agent-1", resource_id="server-01"
            )
            client._request.assert_awaited_once()
            call_args = client._request.call_args
            assert call_args[0][0] == "POST"
            assert call_args[0][1] == "/api/mcp/gate"
            body = call_args[0][2]
            assert body["tool_id"] == "DEPLOY"
            assert body["agent_id"] == "agent-1"
            assert result["decision"]["allow"] is True

    @pytest.mark.asyncio
    async def test_verify_receipt_calls_correct_endpoint(self, client):
        mock_response = {"valid": True, "reason": "Ed25519 signature verified"}
        with patch.object(
            client, "_request", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.verify_receipt(
                evidence_hash="abc123def", signature_b64="c2lnbmF0dXJl"
            )
            call_args = client._request.call_args
            assert call_args[0][1] == "/api/trustatom/verify"
            body = call_args[0][2]
            assert body["evidence_hash"] == "abc123def"
            assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_verify_receipt_includes_payload_when_provided(self, client):
        mock_response = {"valid": True}
        with patch.object(
            client, "_request", new_callable=AsyncMock, return_value=mock_response
        ):
            await client.verify_receipt(
                evidence_hash="abc",
                signature_b64="sig",
                receipt_payload={"action": "DEPLOY"},
            )
            body = client._request.call_args[0][2]
            assert body["receipt_payload"] == {"action": "DEPLOY"}

    @pytest.mark.asyncio
    async def test_check_policy_sends_dry_run_flag(self, client):
        mock_response = {"decision": {"allow": True}, "dry_run": True}
        with patch.object(
            client, "_request", new_callable=AsyncMock, return_value=mock_response
        ):
            await client.check_policy(
                action="READ_EVIDENCE", agent_id="agent-1", resource_id="data-01"
            )
            body = client._request.call_args[0][2]
            assert body["dry_run"] is True
            assert body["tool_id"] == "READ_EVIDENCE"

    @pytest.mark.asyncio
    async def test_health_check_calls_get_health(self, client):
        mock_response = {"status": "ok", "version": "4.0"}
        with patch.object(
            client, "_request", new_callable=AsyncMock, return_value=mock_response
        ):
            result = await client.health_check()
            client._request.assert_awaited_once_with("GET", "/health")
            assert result["status"] == "ok"


# ── Server Tool Tests ────────────────────────────────────────────────────────


class TestGateDecisionTool:
    """Test the gate_decision MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_valid_json_on_success(self):
        from trust_gate_mcp.server import gate_decision

        mock_result = {
            "decision": {"allow": True, "risk_score": 0.3},
            "tool_id": "GRAPH_READ",
            "trustatom": {"id": "ta_abc123", "signature_b64": "sig=="},
        }
        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.gate_decision.return_value = mock_result
            mock_get.return_value = mock_client

            result = await gate_decision(
                action="GRAPH_READ",
                agent_id="test-agent",
                resource_id="test-res",
            )
            parsed = json.loads(result)
            assert parsed["decision"]["allow"] is True
            assert "trustatom" in parsed

    @pytest.mark.asyncio
    async def test_returns_deny_on_client_error(self):
        from trust_gate_mcp.server import gate_decision

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.gate_decision.side_effect = Exception("connection refused")
            mock_get.return_value = mock_client

            result = await gate_decision(
                action="DEPLOY",
                agent_id="test-agent",
                resource_id="prod-server",
            )
            parsed = json.loads(result)
            assert parsed["decision"]["allow"] is False
            assert "connection refused" in parsed["error"]

    @pytest.mark.asyncio
    async def test_passes_all_parameters(self):
        from trust_gate_mcp.server import gate_decision

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.gate_decision.return_value = {"decision": {"allow": True}}
            mock_get.return_value = mock_client

            await gate_decision(
                action="EXPORT_INTEGRATION",
                agent_id="export-agent",
                resource_id="dataset-42",
                tenant_id="acme",
                env="PRODUCTION",
                parent_decision_id="ta_parent_001",
                human_approved=True,
            )
            mock_client.gate_decision.assert_awaited_once_with(
                action="EXPORT_INTEGRATION",
                agent_id="export-agent",
                resource_id="dataset-42",
                tenant_id="acme",
                env="PRODUCTION",
                parent_decision_id="ta_parent_001",
                human_approved=True,
            )


class TestVerifyReceiptTool:
    """Test the verify_receipt MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_valid_on_good_signature(self):
        from trust_gate_mcp.server import verify_receipt

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.verify_receipt.return_value = {
                "valid": True,
                "reason": "Ed25519 signature verified successfully",
                "public_key_b64": "cHVia2V5",
            }
            mock_get.return_value = mock_client

            result = await verify_receipt(
                evidence_hash="abc123", signature="c2lnbmF0dXJl"
            )
            parsed = json.loads(result)
            assert parsed["valid"] is True
            assert "public_key_b64" in parsed

    @pytest.mark.asyncio
    async def test_handles_invalid_json_payload(self):
        from trust_gate_mcp.server import verify_receipt

        result = await verify_receipt(
            evidence_hash="abc",
            signature="sig",
            receipt_payload="not-valid-json{{{",
        )
        parsed = json.loads(result)
        assert parsed["valid"] is False
        assert "Invalid" in parsed["reason"]

    @pytest.mark.asyncio
    async def test_returns_invalid_on_error(self):
        from trust_gate_mcp.server import verify_receipt

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.verify_receipt.side_effect = Exception("network error")
            mock_get.return_value = mock_client

            result = await verify_receipt(evidence_hash="abc", signature="sig")
            parsed = json.loads(result)
            assert parsed["valid"] is False


class TestCheckPolicyTool:
    """Test the check_policy MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_policy_result(self):
        from trust_gate_mcp.server import check_policy

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_policy.return_value = {
                "decision": {"allow": True, "risk_score": 0.1},
                "dry_run": True,
            }
            mock_get.return_value = mock_client

            result = await check_policy(
                action="READ_EVIDENCE",
                agent_id="audit-agent",
                resource_id="log-archive",
            )
            parsed = json.loads(result)
            assert parsed["decision"]["allow"] is True

    @pytest.mark.asyncio
    async def test_returns_deny_on_error(self):
        from trust_gate_mcp.server import check_policy

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.check_policy.side_effect = Exception("timeout")
            mock_get.return_value = mock_client

            result = await check_policy(
                action="DEPLOY", agent_id="test", resource_id="test"
            )
            parsed = json.loads(result)
            assert parsed["allowed"] is False


class TestHealthTool:
    """Test the health MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_status_on_success(self):
        from trust_gate_mcp.server import health

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.health_check.return_value = {
                "status": "ok",
                "version": "4.0",
            }
            mock_get.return_value = mock_client

            result = await health()
            parsed = json.loads(result)
            assert parsed["status"] == "ok"
            assert parsed["mcp_server_version"] == "0.1.0"

    @pytest.mark.asyncio
    async def test_returns_unreachable_on_error(self):
        from trust_gate_mcp.server import health

        with patch("trust_gate_mcp.server._get_client") as mock_get:
            mock_client = AsyncMock()
            mock_client.health_check.side_effect = Exception("DNS failure")
            mock_get.return_value = mock_client

            result = await health()
            parsed = json.loads(result)
            assert parsed["status"] == "unreachable"
            assert "DNS failure" in parsed["error"]
            assert "mcp_server_version" in parsed
