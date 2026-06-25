# PUBLISH package -- Trust Gate MCP (artifacts #4 + #5, gated)

**Status:** DELIVERY-COMPLETE, held for operator approval. Nothing has been submitted to Smithery; nothing external has changed.

## What this is
A single MCP server exposing four tools, all reusing the merged OAO `mint_receipt` (Ed25519 + ML-DSA-65 + SLH-DSA):

| Tool | Maps to | What it does |
|---|---|---|
| `mint_receipt_for_record_change` | artifact #4 (Relaticle alternative) | Mints a per-change receipt for a CRM record change. Old/new values are SHA-256 hashes; any CRM (Relaticle, hosted, custom) can call it. |
| `audit_my_agent_inventory` | artifact #5 | Ranks a CALLER-PROVIDED list of MCP tools by worst-regret. READ-ONLY (no receipt minted by this tool — the caller can pass the returned manifest to `mint_action_receipt`). |
| `mint_action_receipt` | (general) | Post-quantum receipt for any consequential agent action. |
| `verify_receipt` | (general) | Verify a receipt from the certificate alone, offline. |

## Delivery-completeness evidence
- **10/10 tests pass** (`pytest test_server.py`). Real receipts mint with the full Ed25519 + ML-DSA-65 + SLH-DSA leg set, verify from cert, tamper caught on each tool.
- **Honest scope enforced in code:** `audit_my_agent_inventory`'s response carries the `scope_note` that the MCP protocol does not allow auto-discovery; the audit is **read-only and returns no receipt** -- if the caller wants the audit recorded, they pass the returned `audit_manifest_for_receipt` to `mint_action_receipt` (a separate, side-effecting call).
- **Stdio hygiene:** zero `print()` to stdout (Smithery + the MCP spec require stdout = JSON-RPC channel only).
- **Reuses OAO:** zero new crypto, post-quantum by default.

## Publish paths (Smithery offers three; pick at publish time)

### A. Container deploy from GitHub (recommended, supports Python)
The `smithery.yaml` + `Dockerfile` in this dir are the publish package. Container speaks MCP Streamable HTTP on `/mcp` at `$PORT` (Smithery sets PORT=8081). The HTTP entrypoint is `server_http.py`; stdio still works for local dev via `python server.py`.

Steps (gated for your approval):
1. Push this directory as the root of a public GitHub repo (e.g. `CWNApps/trust-gate-mcp`).
2. Connect the repo at smithery.ai → Deploy.
3. Smithery builds the Dockerfile, runs the container, lists the server.

### B. URL / upstream
Self-host the container anywhere reachable; submit the URL at smithery.ai/new. Smithery proxies + lists, no build.

### C. MCPB stdio bundle
Package `server.py` as a local-install `.mcpb` bundle (no Smithery hosting). Best when the server must read local files / credentials only the user has.

## Honest gaps (G5 of the AGENTS.md leaf — verified-or-ABSTAIN)
- The canonical `smithery.yaml` schema reference page is client-rendered; my research workflow could not WebFetch it directly. The fields used here (`runtime: container`, `startCommand.type: http`, `configSchema`, `build.dockerfilePath`) are corroborated by Smithery's publish.md + community-published `smithery.yaml` examples, but **field names may have drifted**. Validate with whatever Smithery's current CLI provides (`smithery validate` or similar) before submission. If submission fails, fix forward — do not invent fields.

## Hardening (status -- 3 of 4 LANDED, 1 deferred-by-design)

### H1 -- Signing-key volume + bootstrap **(DONE)**
The Dockerfile declares `VOLUME ["/data/oao"]` + `ENV OAO_RECEIPT_KEY=/data/oao/receipt_ed25519.pem`. `bootstrap.py` runs at container start, mints a no-op probe to force OAO to persist the keys, and writes `key_metadata.json {kid, created_at, algorithms, oao_version}`. On subsequent boots it **FAIL-CLOSES** (exit 78) on any of: unreadable metadata, missing `kid` field, or `kid` drift between disk and live key. Without a volume mount the keys still work but rotate per restart -- attach a Smithery volume to `/data/oao`.

### H2 -- In-process token-bucket rate limit **(DONE)**
`rate_limit.py` adds a per-IP token bucket as starlette middleware. Defaults: 60 mint/min, 600 verify/min, 120 default/min, all env-overridable (`RATE_LIMIT_MINT_PER_MIN`, etc.). DoS-hardened against (a) IP-rotation memory growth (FIFO eviction at 4096 buckets per class) and (b) oversized-body amplification (bodies > 64 KiB classify to the default bucket without being parsed). Per-pod, not global -- behind Smithery's gateway this is correct for v1; if usage grows, move the limit to the gateway or a shared Redis bucket.

### H3 -- QUANTUM-ENABLED PQ-required verify **(DONE)**
`verify_receipt(receipt, require_pq=None)`. `require_pq=None` obeys `OAO_REQUIRE_PQ` env (default `true`). When ON, verification **FAILS** if `legs.ml_dsa != "ok"` or `legs.slh_dsa != "ok"`. Defends against signature-stripping where an attacker removes the PQ legs to leave only Ed25519 (which loses ~half its security under a quantum adversary). Callers verifying legacy Ed25519-only receipts pass `require_pq=False` explicitly. ZERO perf cost -- the verifier was already checking all three legs.

### H4 -- QUANTUM-ENABLED kid (key identifier) on every receipt **(DONE)**
Every minted receipt now carries `kid = sha256(verify_pubkey_b64)[:32]` (128 bits, adversarial collision resistance). Lets a verifier comparing two receipts answer "signed by the same notary?" offline, without trusting any registry. The same `kid` is in `key_metadata.json` next to the key, so an operator audit "is this still the same notary as last week?" is a one-line check.

### CORS -- intentionally NOT narrowed yet
`server_http.py` keeps `allow_origins=["*"]`. CORS only protects browser-resident credentials; while the server runs in its current unauthenticated, no-secret mode, wide CORS is the right adoption answer. Narrow `allow_origins` to the gateway's origin in the **same PR that adds bearer auth / cookies / per-tenant config**, not before.

### Test coverage of the hardening
`pytest test_hardening.py` -- **15 tests covering all four items**, including the codex-required edge cases: unreadable-metadata-is-fatal, missing-kid-field-is-fatal, IP-rotation FIFO eviction, PQ-stripping attack detection, env-switch behavior.

## Gated next steps (operator approval)
- Approve push of this directory to a public `CWNApps/trust-gate-mcp` repo.
- Approve the Smithery submission (path A, B, or C).
- Decide whether `openagentontology[pq]` is auto-installed inside the image (current default) or required to be configured by the deployer.
