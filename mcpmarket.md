# Trust Gate — MCP Market Submission

## Title
Trust Gate — Post-Quantum Receipts for Consequential Agent Actions

## Tagline
No Receipt. No Trust.

## Short Description (160 chars)
Mint post-quantum, tamper-evident receipts for consequential agent actions. Verify offline from the certificate alone — no server to trust, no database.

## Long Description

When an agent does something consequential — writes to a CRM, ships data to a third party, deploys — the question afterwards is not "did it seem fine?" but "can you prove what was decided, on what inputs, by which model?"

Trust Gate answers that with a receipt. Every gated action produces a hybrid-signed certificate that:

1. **Hashes the evidence** — old and new values are SHA-256'd, never stored in the clear
2. **Signs it post-quantum** — Ed25519 for today, ML-DSA-65 (FIPS 204) for a quantum tomorrow
3. **Verifies offline** — from the certificate alone, no server call and no database lookup
4. **Carries a notary `kid`** — so anyone can confirm two receipts came from the same signer

A screenshot is not evidence. A log line an agent wrote about itself is not evidence. A signature over hashed inputs, verifiable by someone who does not trust you, is.

## Architecture note

As of 0.2.0 this server is **self-contained**. It mints locally through the open-source
[OpenAgentOntology](https://github.com/CWNApps/openagentontology) primitive. There is no
hosted backend dependency, no API key, and no account required to run it.

## Signing legs — what you actually get

| Install | Legs |
|---|---|
| `pip install trust-gate-mcp` | Ed25519 + ML-DSA-65 (FIPS 204). Pure Python, no native toolchain. |
| `pip install "trust-gate-mcp[slh]"` | Adds SLH-DSA (FIPS 205), the hash-based leg that survives a lattice break. Native (`liboqs`). |

PQ-required verify is **on by default** and demands at least one verified post-quantum leg,
which defeats signature-stripping downgrade attacks. The dual-leg default satisfies it; the
`[slh]` install adds hash-based diversity on top.

## Tools (7)

| Tool | What it does | Risk |
|------|--------------|------|
| `mint_receipt_for_record_change` | Receipt for one CRM record change; values hashed | Low |
| `audit_my_agent_inventory` | Rank a caller-supplied tool list by worst-regret. **Read-only** | Low |
| `mint_action_receipt` | Receipt for any consequential action, with signed attestation provenance | Low |
| `verify_receipt` | Offline verification from the certificate alone | Low |
| `gate_decision` | Two-phase PREVIEW → COMMIT gate with execution permit | Medium |
| `check_egress` | Classify data PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED; blocks RESTRICTED | Medium |
| `run_exit_drill` | Vendor exit-readiness check. Informational, no side effects | Low |

`audit_my_agent_inventory` ranks only what the caller passes in. MCP does not let a server
enumerate its host's other servers, and the tool says so in its own output rather than
implying a discovery power it does not have.

## Installation

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trust-gate": {
      "command": "uvx",
      "args": ["trust-gate-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add trust-gate -- uvx trust-gate-mcp
```

### Cursor / Zed / Windsurf / Cline

All support stdio MCP servers. Point the client at `uvx trust-gate-mcp`. No API key needed.

## Configuration

No required environment variables. All optional:

| Env Var | Purpose | Default |
|---------|---------|---------|
| `OAO_RECEIPT_KEY` | Persistent signing-key path. **Set this in production** — otherwise the key regenerates per restart and old receipts stop verifying | `~/.openagentontology/receipt_ed25519.pem` |
| `TRUST_GATE_REQUIRE_PQ` | Require a verified PQ leg on verify | `true` |
| `TRUST_GATE_BEARER_TOKEN` | Bearer auth for the HTTP transport | unset |
| `TRUST_GATE_ALLOWED_ORIGINS` | CORS allowlist for HTTP | unset |
| `PORT` | HTTP transport port | `8081` |

## Hardening

* **H1** persistent key + bootstrap that **fails closed** on `kid` drift
* **H2** per-IP token-bucket rate limit (FIFO eviction + body cap)
* **H3** PQ-required verify (defeats signature-stripping)
* **H4** 128-bit `kid` on every receipt (offline same-notary check)
* 33/33 tests, including adversarial PQ-strip and IP-rotation simulations

## Pricing

The MCP server is **free and Apache-2.0** — self-contained, no account, no key.

The hosted Trust Gate platform (managed policy, retained decision graph, support SLAs) is
priced separately at <https://cwn-trust-gate.onrender.com/pricing>.

## Compliance

Receipts are native evidence for:

- **EU AI Act Article 50** (transparency obligations, effective 2026-08-02)
- **SOC 2 Type II** (decision audit trails)
- **NIST AI Risk Management Framework**
- **CMMC** (controlled data handling)

## License
Apache-2.0

## Links
- Homepage: https://cwn-trust-gate.onrender.com
- GitHub: https://github.com/CWNApps/trust-gate-mcp
- Signing primitive: https://github.com/CWNApps/openagentontology
- Pricing: https://cwn-trust-gate.onrender.com/pricing

## Support
- Email: `developers@cyberwarriornetwork.com`
- Issues: https://github.com/CWNApps/trust-gate-mcp/issues
