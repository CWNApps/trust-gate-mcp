# Trust Gate MCP

Post-quantum, tamper-evident receipts for consequential agent actions, as an MCP server.

Seven tools, one shared signing primitive: the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) `mint_receipt`.

**What actually gets signed depends on what you install** -- OAO detects its backend at import time, so this is worth stating plainly rather than advertising the best case:

| Install | Legs | Notes |
|---|---|---|
| `pip install trust-gate-mcp` | Ed25519 + ML-DSA-65 (FIPS 204) | Default. Pure Python (`dilithium-py`), no native toolchain. Satisfies PQ-required mode. |
| `pip install "trust-gate-mcp[slh]"` | Ed25519 + ML-DSA-65 + SLH-DSA (FIPS 205) | Adds the hash-based diversity leg via `liboqs`, which survives a lattice break. Native dependency. |

PQ-required verify (the default) demands **at least one** verified post-quantum leg, so the
dual-leg default is a real post-quantum posture, not a downgrade -- but only the `[slh]` install
gives you the hash-based third leg.

| Tool | What it does |
|---|---|
| `mint_receipt_for_record_change` | Mints a post-quantum receipt for a CRM record change. Works with any CRM (open-core Relaticle, hosted CRMs via their own MCP, custom). Old/new values are SHA-256 hashes. |
| `audit_my_agent_inventory` | Ranks a CALLER-PROVIDED list of MCP tools by worst-regret if they act. **Read-only.** Cannot auto-discover other servers -- MCP protocol does not allow that. |
| `mint_action_receipt` | Post-quantum receipt for any consequential agent action. |
| `verify_receipt` | Verify a receipt from the certificate alone -- offline, no DB. Defaults to PQ-required mode. |
| `gate_decision` | Two-phase decision gate. PREVIEW returns risk assessment + preview_id without acting. COMMIT verifies inputs match and mints a tamper-evident receipt with execution permit. |
| `check_egress` | Egress classification. Scans data for sensitivity markers and classifies as PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. Blocks RESTRICTED. Returns classification + retention info + receipt. |
| `run_exit_drill` | Vendor exit readiness drill. Checks local signing key, local model access (Ollama), and local data export. Returns step-by-step results + receipt. Informational, no side effects. |

## Quantum Hardening (pol.must_do.150 reference implementation)

* **H1** key persistence + bootstrap with FAIL-CLOSED kid-drift check
* **H2** per-IP token-bucket rate limit (DoS-hardened: FIFO eviction + body cap)
* **H3** PQ-required verify (defeats signature-stripping downgrade attacks)
* **H4** 128-bit `kid` on every minted receipt (offline same-notary check)
* Optional bearer-auth toggle + narrowed CORS via `TRUST_GATE_BEARER_TOKEN` + `TRUST_GATE_ALLOWED_ORIGINS`
* 33/33 tests including adversarial PQ-strip + IP-rotation attack simulations

See [PUBLISH.md](./PUBLISH.md) for the full hardening status table.

## Install (stdio)

```bash
pip install trust-gate-mcp
trust-gate-mcp
```

Add `[slh]` for the hash-based third leg. From a checkout, `pip install -e ".[dev]"` then
`python -m trust_gate_mcp`.

## Container deploy (Smithery / any container host)

```bash
docker build -t trust-gate-mcp .
docker run -p 8081:8081 -v trust-gate-data:/data/oao trust-gate-mcp
```

The volume mount on `/data/oao` is **required for production** -- without it the signing key rotates per restart and breaks long-running verification chains. The persistent `key_metadata.json` holds the notary's `kid`; the bootstrap step refuses to start if it drifts.

## License

Apache-2.0. Built on the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) primitive.
