---
name: trust-gate
description: Mint and verify post-quantum, tamper-evident decision receipts for AI agent actions. Pre-execution OPA policy gate (ALLOW/DENY/ESCALATE) plus Ed25519-signed TrustAtom receipts, independently verifiable offline.
version: 0.2.0
metadata:
  openclaw:
    requires:
      env:
        - TRUST_GATE_API_KEY
      bins:
        - curl
    primaryEnv: TRUST_GATE_API_KEY
---

# Trust Gate

Cryptographically signed decision receipts for AI agent actions. Every consequential
action an agent takes -- a deploy, a database write, a policy change -- can be gated
through OPA policy evaluation BEFORE it happens, and mints a tamper-evident receipt
AFTER it happens. The receipt is Ed25519-signed (offline-verifiable from the
certificate alone, no trust in the issuer required).

## When to Use

- An agent is about to take a consequential, hard-to-reverse action and you want a
  pre-execution policy check (ALLOW / DENY / ESCALATE) before it runs
- You need a tamper-evident record of what an agent decided, under what policy, with
  what evidence, that a third party (auditor, regulator, insurer) can verify without
  trusting your logs
- You're building compliance evidence for EU AI Act Art 12, SOC 2, or NIST AI RMF and
  need machine-readable decision receipts, not just text logs

## When Not to Use

- Low-stakes, easily reversible actions (read-only queries, draft generation) where a
  receipt adds no decision value
- You need real-time blocking with sub-millisecond latency at very high QPS -- the
  policy gate call adds network round-trip time

## Quick Start

```bash
curl -X POST https://cwn-trust-gate.onrender.com/mcp \
  -H "Authorization: Bearer $TRUST_GATE_API_KEY" \
  -d '{"tool": "gate_decision", "arguments": {
    "action": "DEPLOY",
    "agent_id": "my-agent-01",
    "resource_id": "prod-service-x",
    "env": "PRODUCTION"
  }}'
```

## Tools

| Tool | Purpose |
|---|---|
| `gate_decision` | Gate an AI decision through OPA policy and mint a cryptographic receipt. |
| `verify_receipt` | Verify a TrustAtom receipt's Ed25519 signature, offline. |
| `check_policy` | Dry-run a policy evaluation without minting a receipt. |
| `health` | Check Trust Gate connectivity and service status. |

## Honesty notes

ML-DSA-65 post-quantum cosignature support is part of the protocol; verify any
specific deployment's PQ status via the `health` tool before relying on it for
long-horizon post-quantum guarantees. This server defaults to PQ-required verify
(`require_pq=true`) -- verification fails closed if the PQ legs are missing.

## Links

- Demo: https://cwn-trust-gate.onrender.com
- MCP registry: `io.github.CWNApps/trust-gate-mcp`
- Protocol spec: https://github.com/CWNApps/openagentontology
- License: Apache-2.0
