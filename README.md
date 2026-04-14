# Trust Gate MCP Server

**Decision Trust for AI Agents** — gate any AI decision through OPA policies and mint Ed25519 cryptographic receipts.

> No Receipt. No Trust.

## What It Does

Trust Gate adds accountability to AI agent decisions. When your agent calls `gate_decision`, Trust Gate:

1. **Evaluates** the decision against OPA policies (allow/deny + risk score)
2. **Signs** an Ed25519 cryptographic receipt (TrustAtom) if approved
3. **Stores** the decision in an immutable Neo4j graph
4. **Returns** proof that the decision was evaluated, authorized, and recorded

Every receipt is cryptographically signed and independently verifiable. If an AI agent can't produce a receipt, you can't trust the decision.

## Installation

```bash
# Using uv (recommended)
uv pip install trust-gate-mcp

# Using pip
pip install trust-gate-mcp
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRUST_GATE_URL` | No | `https://cwn-trust-gate.onrender.com` | Trust Gate API base URL |
| `TRUST_GATE_API_KEY` | Yes | — | Bearer token for authentication |
| `TRUST_GATE_TENANT` | No | `default` | Default tenant ID |
| `TRUST_GATE_TIMEOUT` | No | `30` | HTTP timeout in seconds |

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trust-gate": {
      "command": "uvx",
      "args": ["trust-gate-mcp"],
      "env": {
        "TRUST_GATE_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Usage with Claude Code

```bash
claude mcp add trust-gate -- uvx trust-gate-mcp
```

## Available Tools

### `gate_decision`

Submit an AI decision for policy evaluation and cryptographic receipt minting.

```
action: "DEPLOY"
agent_id: "my-deploy-agent"
resource_id: "prod-server-01"
env: "PRODUCTION"
```

Returns: allow/deny decision, risk score, and signed TrustAtom receipt.

### `verify_receipt`

Verify a TrustAtom receipt's Ed25519 signature. Purely mathematical verification — no trust in the server required.

```
evidence_hash: "a1b2c3..."
signature: "base64-encoded-ed25519-signature"
```

Returns: valid (bool), public key, and reason.

### `check_policy`

Dry-run a policy evaluation without minting a receipt. Use for pre-flight checks.

```
action: "EXPORT_INTEGRATION"
agent_id: "export-agent"
resource_id: "customer-data"
```

Returns: allow/deny, risk score, classification. No state changes.

### `health`

Check Trust Gate connectivity and service status.

Returns: service status, version, and environment details.

## Action Types

| Action | Risk Level | Receipt Required |
|--------|-----------|-----------------|
| `READ_EVIDENCE` | Low | No |
| `GRAPH_READ` | Low | No |
| `CODE_GENERATION` | Medium | No |
| `GRAPH_WRITE` | Medium | Yes |
| `EXPORT_INTEGRATION` | High | Yes |
| `DEPLOY` | High | Yes |
| `MODIFY_POLICY` | Critical | Yes + Human Approval |

## Why This Exists

If a foundation model can replicate your product in a single API call, you don't have a product. Trust Gate provides something models can't replicate: **cryptographic proof that decisions were evaluated, authorized, and recorded.**

The receipts are temporally unique (signed at decision time), cryptographically bound (Ed25519), and relationally structured (linked in a decision graph). A model cannot retroactively generate this state.

## Development

```bash
cd mcp/trust-gate-server
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 — Cyber Warrior Network
