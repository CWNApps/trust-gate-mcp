# Trust Gate MCP

Post-quantum, tamper-evident receipts for consequential agent actions, as an MCP server.

Four tools, one shared signing primitive (the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) `mint_receipt`: Ed25519 + ML-DSA-65 + SLH-DSA):

| Tool | What it does |
|---|---|
| `mint_receipt_for_record_change` | Mints a post-quantum receipt for a CRM record change. Works with any CRM (open-core Relaticle, hosted CRMs via their own MCP, custom). Old/new values are SHA-256 hashes. |
| `audit_my_agent_inventory` | Ranks a CALLER-PROVIDED list of MCP tools by worst-regret if they act. **Read-only.** Cannot auto-discover other servers -- MCP protocol does not allow that. |
| `mint_action_receipt` | Post-quantum receipt for any consequential agent action. |
| `verify_receipt` | Verify a receipt from the certificate alone -- offline, no DB. Defaults to PQ-required mode. |

## Quantum Hardening (pol.must_do.150 reference implementation)

* **H1** key persistence + bootstrap with FAIL-CLOSED kid-drift check
* **H2** per-IP token-bucket rate limit (DoS-hardened: FIFO eviction + body cap)
* **H3** PQ-required verify (defeats signature-stripping downgrade attacks)
* **H4** 128-bit `kid` on every minted receipt (offline same-notary check)
* Optional bearer-auth toggle + narrowed CORS via `TRUST_GATE_BEARER_TOKEN` + `TRUST_GATE_ALLOWED_ORIGINS`
* 33/33 tests including adversarial PQ-strip + IP-rotation attack simulations

See [PUBLISH.md](./PUBLISH.md) for the full hardening status table.

## Local dev (stdio)

```bash
pip install mcp "openagentontology[pq]"
python server.py
```

## Container deploy (Smithery / any container host)

```bash
docker build -t trust-gate-mcp .
docker run -p 8081:8081 -v trust-gate-data:/data/oao trust-gate-mcp
```

The volume mount on `/data/oao` is **required for production** -- without it the signing key rotates per restart and breaks long-running verification chains. The persistent `key_metadata.json` holds the notary's `kid`; the bootstrap step refuses to start if it drifts.

## License

Apache-2.0. Built on the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) primitive.
