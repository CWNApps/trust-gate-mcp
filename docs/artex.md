# Using TrustGate MCP with ARTEX

[ARTEX](https://github.com/BaaRai/ARTEX) is a self-hosted, LLM-driven autonomous penetration testing platform
(AGPL-3.0, a separate project). Its planner and workers can call remote MCP servers, so a running ARTEX can ask this
server for a verdict before a consequential step and keep a signed receipt of the answer. Nothing in ARTEX has to
change.

## What you get, and what you do not

* **A verdict and a receipt when a worker asks.** A worker that calls `gate_decision` gets ALLOW, DENY or
  ESCALATE, and on COMMIT a receipt signed with Ed25519 (plus ML-DSA-65 when the post-quantum backend is installed).
* **Every pentest action escalates or is denied.** Scanning, fuzzing, exploitation, credential use, data dumps and
  similar steps never get ALLOW: the gate allows only a closed list of read-only names (see "What the gate does and does
  not do" in the [README](../README.md)). `tests/test_artex_actions.py` pins this for the actions ARTEX workers
  typically name. An ESCALATE is your cue to use ARTEX's own approval step.
* **It is advisory.** The gate sees only what a worker chooses to send. It does not watch ARTEX, block its tools or
  confirm afterwards that an action happened. ARTEX v0.6.0 cannot keep its own Bash and nmap calls inside the task scope,
  so limit the ARTEX host's network egress to the authorized targets, your LLM provider and this server.

## Run the server over HTTP

```bash
docker build -t trust-gate-mcp .
docker run -d --name trust-gate-mcp \
  -p 127.0.0.1:8081:8081 \
  -v trust-gate-data:/data/oao \
  -e TRUST_GATE_BEARER_TOKEN="$(openssl rand -hex 32)" \
  -e TRUST_GATE_ALLOWED_ORIGINS="https://artex.internal.example" \
  trust-gate-mcp
```

* Always set `TRUST_GATE_BEARER_TOKEN`. Without it, anyone who can reach the port gets receipts signed with your key.
* Keep the `/data/oao` volume, or the signing key, and with it the `kid` you pin, changes on every restart.
* If ARTEX runs on another host, put the server behind TLS. Do not set `insecure` on the ARTEX side.
* Record the server's `kid` (from any receipt) so you can verify receipts against it later.

## Register it in ARTEX

In ARTEX, open the MCP section of system settings and add a remote server:

| Field | Value |
|---|---|
| Transport | `http` (Streamable HTTP) |
| URL | `https://<your-host>/mcp` (or `http://127.0.0.1:8081/mcp` on the same host) |
| Headers | `{"Authorization": "Bearer <the token above>"}` |

Send the token in `Authorization`, not a custom header such as `X-API-Key`. ARTEX's MCP client follows redirects;
Go drops `Authorization` when a redirect leaves the host, but carries custom headers along. This server answers
`/mcp` in place and never redirects (also pinned by `tests/test_artex_actions.py`).

Use one token per ARTEX deployment, so you can rotate one without touching the others.

## Tell the agents to use it

ARTEX agents call a tool only when they see a reason to. Put this in the task goal, or in the worker prompt:

> Before any exploit, credential use, data download or state-changing request, call `gate_decision` with
> `phase: "PREVIEW"`, then `phase: "COMMIT"` with the returned `preview_id`. Use a short `action` such as
> "exploit sql injection" and the target URL or host as `resource`. If the verdict is ESCALATE, ask for human approval
> before continuing; if it is DENY, do not continue. For each confirmed finding, call `mint_action_receipt` with
> `agent_id` "artex", `operation` the finding title and `target` the affected asset.

The action, resource, operation and target are stored in clear text in the signed receipt. Never put credentials, tokens or captured
response bodies in them. `context` is stored only as a hash.

## Check a receipt

```bash
# from any MCP client connected to the same server
verify_receipt(receipt=<receipt>, expected_kid="<your kid>")
```

A receipt counts as a gate verdict from your server only when `signer_pinned` is true, `verified.issuer_tool` is
`gate_decision` and `verified.operation` is `decision_gate_commit`.
