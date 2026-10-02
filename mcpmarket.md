# Trust Gate — MCP Market Submission

## Title
Trust Gate — Hybrid-Signed Receipts for Consequential Agent Actions

## Tagline
No Receipt. No Trust.

## Short Description (146 chars, limit 160)
Mint tamper-evident receipts for agent actions, gate read-only actions with a signed ALLOW / DENY / ESCALATE verdict, and verify receipts offline.

## Long Description

When an agent does something consequential — writes to a CRM, ships data to a third party, deploys — the question afterwards is not "did it seem fine?" but "can you prove what was decided, on what inputs, by which model, as the caller says?"

Trust Gate answers that with a receipt. Every receipt is a hybrid-signed certificate that:

1. **Hashes the evidence** — in the record-change tool, old and new values are SHA-256 hashed (unsalted; the gate records its action and resource in clear text)
2. **Signs it twice** — Ed25519, plus an ML-DSA-65 signature (the default backend is unhardened; see below)
3. **Verifies offline** — integrity and signatures from the certificate alone, no server call and no database lookup
4. **Carries a signer `kid`** — a fingerprint of the Ed25519 key, so you can pin the key you trust (the post-quantum keys in a receipt are not covered by it)

A screenshot is not evidence. A log line an agent wrote about itself is not evidence. A signature over hashed inputs, checkable offline against a key you have pinned, is.

## What the gate does (and does not)

`gate_decision` returns ALLOW, DENY or ESCALATE and signs the verdict. ALLOW is an allowlist: a known read verb followed only by known nouns, a plain identifier, a relative resource (no leading slash) that is not hidden, not a phrase, and not a configuration, data, key, state or archive file, and no risky or sensitive word. Everything else escalates or is denied. The word lists are finite: a secret under a name on no list is not detected. It applies only to actions your code routes through it; it does not observe or block what an agent does, and it judges names, not behaviour.

## Architecture note

This server is **self-contained**. It mints locally through the open-source
[OpenAgentOntology](https://github.com/CWNApps/openagentontology) primitive. There is no
hosted backend dependency, no API key, and no account required to run it.

## Signing legs — what you actually get

| Install | Legs |
|---|---|
| `pip install trust-gate-mcp` | Ed25519 + ML-DSA-65 (FIPS 204). The ML-DSA leg is `dilithium-py`, a pure-Python library whose own README says it must not be used for cryptographic applications; treat it as unhardened. |
| `pip install "trust-gate-mcp[slh]"` | Installs `liboqs-python` (needs the native liboqs library; preferred for ML-DSA-65). It adds a hash-based leg only if that liboqs still ships `SPHINCS+-SHA2-128s-simple` (pre-standard, not byte-compatible with FIPS 205); liboqs 0.16.0 removed it, so today this gives the native ML-DSA backend and no hash-based leg. If liboqs cannot be imported the primitive silently falls back to `dilithium-py`. |

PQ-required verify is **on by default** and demands at least one verified post-quantum leg.
That shows a post-quantum signature is present and valid, not whose key made it. The default install satisfies the check; it does not make the pure-Python backend production-grade.
`run_exit_drill` reports which backend is active.

## Tools (7)

| Tool | What it does | Risk |
|------|--------------|------|
| `mint_receipt_for_record_change` | Receipt for one CRM record change; values hashed | Low |
| `audit_my_agent_inventory` | Rank a caller-supplied tool list by worst-regret. **Read-only, mints no receipt** | Low |
| `mint_action_receipt` | Receipt for any consequential action; attestation values are caller claims, signed not verified; gate-looking decisions refused (best effort; to accept a gate verdict, pin the signer and check `issuer_tool`) | Low |
| `verify_receipt` | Offline verification from the certificate alone; refuses unsigned receipts; optional `expected_kid` pin (counts only when that key's own Ed25519 signature verifies) | Low |
| `gate_decision` | Two-phase PREVIEW → COMMIT gate: ALLOW / DENY / ESCALATE verdict, signed receipt, GRANTED permit only on ALLOW. Applies only to actions routed through it | Medium |
| `check_egress` | Flag sensitive markers: NO_MARKERS_FOUND/INTERNAL/CONFIDENTIAL/RESTRICTED; credential-shaped values and personal identifiers are RESTRICTED and set `blocked` (the tool cannot block anything itself; NO_MARKERS_FOUND is not clearance) | Medium |
| `run_exit_drill` | Vendor exit-readiness check. Informational; it signs one receipt, which creates the signing key on a host that has none yet | Low |

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
| `OAO_RECEIPT_KEY` | Persistent signing-key path. **Set this in production** — in a container without a volume the key changes on restart: old receipts still verify from their own certificate, but a pinned `kid` stops matching new ones | `~/.openagentontology/receipt_ed25519.pem` |
| `TRUST_GATE_REQUIRE_PQ` | Require a verified PQ leg on verify. Only `0`, `false`, `no` or `off` turn it off | `true` |
| `TRUST_GATE_BEARER_TOKEN` | Bearer auth for the HTTP transport. **Set it when hosting over HTTP**; without it anyone who can reach the server can obtain signed receipts | unset |
| `TRUST_GATE_ALLOWED_ORIGINS` | CORS allowlist for HTTP | unset |
| `TRUST_GATE_FORWARDED_ALLOW_IPS` | Proxy addresses whose `X-Forwarded-For` is trusted; set it to your proxy, or clients can choose their own identity for rate limiting | any |
| `TRUST_GATE_CHANNELS` | Extra `?via=` labels the HTTP counter records (comma separated) | unset |
| `PORT` | HTTP transport port | `8081` |

## Hardening

* **H1** persistent key + bootstrap that **fails closed** on `kid` drift
* **H2** per-IP token-bucket rate limit (FIFO eviction), classified by the parsed tool name; a body over 64 KiB or one it cannot parse is charged to the signing budget; a request over 1 MiB gets 413; client identity follows `TRUST_GATE_FORWARDED_ALLOW_IPS`
* **H3** PQ-required verify (refuses unsigned receipts and receipts with no verified post-quantum leg)
* **H4** 128-bit `kid` on every receipt, recomputed from the canonical key bytes on verify
* A test suite that pins every verb and noun of the gate individually, with adversarial cases for classifier bypass, receipt forgery and PQ stripping

## Pricing

The MCP server is **free and Apache-2.0** — self-contained, no account, no key.

The hosted Trust Gate platform (managed policy, retained decision graph) is
priced separately at <https://cwn-trust-gate.onrender.com/pricing>.

## Evidence, not certification

Receipts are tamper-evident records that can support an audit trail. They do not make a system compliant with any law or framework, and this project does not claim conformity with the EU AI Act, SOC 2, the NIST AI RMF or CMMC.

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
