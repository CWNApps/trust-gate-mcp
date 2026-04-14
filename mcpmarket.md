# Trust Gate — MCP Market Submission

## Title
Trust Gate — Policy-Gated AI Decisions with Cryptographic Receipts

## Tagline
No Receipt. No Trust.

## Short Description (160 chars)
Gate AI agent decisions through OPA policies and mint Ed25519 cryptographic receipts. Mathematical proof every decision was evaluated, authorized, recorded.

## Long Description

Trust Gate adds cryptographic accountability to AI agent decisions. When an agent calls a Trust Gate tool, every decision is:

1. **Evaluated** against declarative OPA policies (allow/deny + risk score)
2. **Signed** with Ed25519 before execution (sub-3ms cryptographic budget)
3. **Recorded** in an immutable Neo4j decision graph
4. **Verifiable** by anyone — the receipt is mathematical, not server-trust-based

If an AI agent can't produce a signed TrustAtom receipt, you can't trust the decision actually happened under policy. This is what "SOC 2 for AI Agents" looks like.

## Why This Exists

Foundation models are a commodity. Any agent built on top can be replicated in a single API call. What can't be replicated is **proof that decisions were evaluated, authorized, and recorded** — receipts are temporally unique (signed at decision time), cryptographically bound (Ed25519), and relationally structured (linked in a decision graph).

A model cannot retroactively generate this state. Regulators can't accept screenshots as AI governance evidence. Insurers can't price risk without auditable trails. Customers can't trust agents without proof of boundaries.

Trust Gate is the boundary layer agents are missing.

## Tools (4)

| Tool | What it does | Risk |
|------|--------------|------|
| `gate_decision` | Evaluate action + mint Ed25519 receipt | Medium |
| `verify_receipt` | Mathematically verify any receipt signature | Low |
| `check_policy` | Dry-run policy without minting (pre-flight) | Low |
| `health` | Check Trust Gate connectivity | Low |

## Action Types

| Action | Risk | Receipt | Notes |
|--------|------|---------|-------|
| `READ_EVIDENCE` | Low | No | Read-only queries |
| `GRAPH_READ` | Low | No | Graph traversal |
| `CODE_GENERATION` | Medium | No | LLM-generated code |
| `GRAPH_WRITE` | Medium | Yes | Graph modifications |
| `EXPORT_INTEGRATION` | High | Yes | Cross-system data egress |
| `DEPLOY` | High | Yes | Production deployments |
| `MODIFY_POLICY` | Critical | Yes + Human | Policy mutations |

## Installation

### Claude Desktop

Add to `claude_desktop_config.json`:

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

### Claude Code

```bash
claude mcp add trust-gate -- uvx trust-gate-mcp
```

### Cursor / Zed / Windsurf / Cline

All support stdio MCP servers. Config path varies by client — point to `uvx trust-gate-mcp` and set `TRUST_GATE_API_KEY`.

## Configuration

| Env Var | Required | Default |
|---------|----------|---------|
| `TRUST_GATE_API_KEY` | Yes | — |
| `TRUST_GATE_URL` | No | `https://cwn-trust-gate.onrender.com` |
| `TRUST_GATE_TENANT` | No | `default` |
| `TRUST_GATE_TIMEOUT` | No | `30` |

## Pricing

Get an API key at https://cwn-trust-gate.onrender.com/pricing:

- **Starter** — $500/mo — unlimited receipts, 1 tenant
- **Professional** — $2,500/mo — 5 tenants, 24h support SLA, ML-DSA-65 quantum-safe preview
- **Enterprise** — $10,000/mo — unlimited tenants, 4h SLA, custom OPA, on-prem option

Free tier for open-source agents — email `developers@cyberwarriornetwork.com`.

## Compliance

Trust Gate receipts are native evidence for:

- **EU AI Act Article 50** (transparency obligations, effective 2026-08-02)
- **SOC 2 Type II** (decision audit trails)
- **NIST AI Risk Management Framework**
- **CMMC** (controlled data handling)

## Technical Details

- **Signing**: Ed25519 curve (NIST SP 800-186), sub-3ms per signature
- **Storage**: Neo4j immutable graph (append-only, Landauer principle)
- **Policy**: Open Policy Agent (OPA) with Rego rules
- **Transport**: MCP stdio (JSON-RPC 2.0)
- **Authentication**: Bearer token
- **3-tier degradation**: Full (Neo4j + OPA + API) → Partial (file receipts) → Demo (sandbox mode)

## License
Apache-2.0

## Links
- Homepage: https://cwn-trust-gate.onrender.com
- GitHub: https://github.com/cyber-warrior-network/trust-gate-mcp
- Pricing: https://cwn-trust-gate.onrender.com/pricing
- Docs: https://cwn-trust-gate.onrender.com/api-reference

## Support
- Email: `developers@cyberwarriornetwork.com`
- Issues: https://github.com/cyber-warrior-network/trust-gate-mcp/issues
