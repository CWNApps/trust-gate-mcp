# Changelog

## 0.2.0 -- 2026-06-25

**Architecture change.** Trust Gate MCP evolves from a thin client of the hosted
`cwn-trust-gate.onrender.com` backend into a SELF-CONTAINED MCP server that mints
post-quantum receipts locally via the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology)
primitive. No hosted backend dependency.

### Tools (full set rewritten)
- `mint_receipt_for_record_change(...)` -- tamper-evident per-change receipt for any CRM
- `audit_my_agent_inventory(inventory)` -- worst-regret ranking of a CALLER-PROVIDED list (READ-ONLY)
- `mint_action_receipt(...)` -- general-purpose consequential-action receipt
- `verify_receipt(receipt)` -- offline verify from the certificate alone

The v0.1.0 tools (`gate_decision`, `check_policy`, `health`) are removed from the MCP
surface. The `client.py` + `config.py` modules are kept under `src/trust_gate_mcp/` for
callers that still want to talk to the hosted backend; `build_server()` does not use them.

### Quantum Hardening (CWN pol.must_do.150 reference)
- H1: persistent signing-key volume + bootstrap (FAIL-CLOSED on kid drift)
- H2: per-IP token-bucket rate limit, DoS-hardened (FIFO eviction + body cap)
- H3: PQ-required verify (defeats signature-stripping)
- H4: 128-bit `kid` on every minted receipt (offline same-notary check)

Optional bearer-auth toggle via `TRUST_GATE_BEARER_TOKEN`; CORS narrows to
`TRUST_GATE_ALLOWED_ORIGINS` when bearer is on.

33/33 hardened-server tests + adversarial PQ-strip and IP-rotation attack simulations.

## 0.1.0 -- 2026-04-14

Initial release. Thin MCP client of the hosted Trust Gate backend at
`cwn-trust-gate.onrender.com`. Tools: `gate_decision`, `verify_receipt`,
`check_policy`, `health`. Apache-2.0.
