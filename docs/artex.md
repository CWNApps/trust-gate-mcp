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

## Receipt every finding (`trust-gate-artex`)

The sections above let ARTEX agents ask for receipts. They depend on the agent choosing to ask. `trust-gate-artex` does not:
it runs next to your ARTEX, reads the findings over ARTEX's own REST API, and signs one receipt per finding, and one more
each time a finding changes. You run it. Nothing leaves your network, and the receipts are signed with your key.

A receipt says: the holder of this signing key saw this ARTEX API return this finding, with these evidence hashes, at about
this time. It does not say the finding is true, that anyone authorised the test, or that ARTEX did not alter the finding
before the tool read it. The signed record holds hashes and ids only. Hostnames, URLs, evidence text and request or response
bytes are never written to a receipt (the evidence bodies are downloaded only to be hashed).

```bash
pip install "trust-gate-mcp[pq]"                       # same package, installs the trust-gate-artex command
export OAO_RECEIPT_KEY=/srv/example/keys/receipt.pem   # your signing key; back it up, and keep it off the ARTEX host if you can
export ARTEX_URL=http://127.0.0.1:8787                 # no path, no credentials in the URL
export ARTEX_USERNAME=admin
export ARTEX_PASSWORD_FILE=/srv/example/secrets/artex-password   # or ARTEX_PASSWORD; never put it on the command line

trust-gate-artex sync --out /srv/example/artex-receipts --instance-name acme-lab --init-key   # --init-key only the first time
```

* **Output.** `OUT/findings/<finding id>/000001.record.json` and `000001.receipt.json`, then `000002...` when the finding
  changes. `OUT` must be an absolute path on a local disk (the tool uses a lock file), and is created private (0700).
* **stdout** is one JSON summary: `minted`, `unchanged`, `failed`, `gone`, `complete`, `signer_kid`, `pq_signed`, and a
  `failures` list of `{key, reason}`. Exit 0 means every listed finding is receipted and nothing is missing. Exit 1 means
  something failed or a finding disappeared. Exit 2 is a usage error. Exit 3 is a pre-flight refusal (key missing, lock held,
  ARTEX URL unsafe, name or origin differs from `OUT/INSTANCE`).
* **Unchanged findings** are skipped without downloading their bodies, by comparing ARTEX's own claimed hashes. Add
  `--verify-bodies` once a week to re-hash them all and catch evidence that changed behind an unchanged finding.
* **A finding deleted in ARTEX** is reported as `finding_gone` on every run until you acknowledge it with `--ack-gone <id>`.
* **Changing the ARTEX address or instance label** needs `--rebind`. The label is inside every signed target, so renaming
  an instance starts new chains; keep the label stable.
* **Cron.** Run it as a dedicated user, hourly at most is plenty: `17 * * * * trust-gate-artex sync --out ... --instance-name ...`.
  Alert on any non-zero exit. A run holds a lock, so overlapping runs refuse (exit 3) instead of racing.
* **ARTEX credentials.** ARTEX has no scoped tokens: the login you give this tool is a full admin login (a 7-day token).
  Create a separate account for it, keep the password file at mode 0600, and if ARTEX is reached through a reverse proxy,
  allow only the five read paths the tool uses: `POST /api/auth/login`, `GET /api/health`, `GET /api/exploration/findings`,
  `GET /api/exploration/findings/{id}`, and `GET /api/exploration/findings/{id}/traffic/{binding}/body`. The tool never
  follows a redirect and ignores proxy environment variables.

Verify, on any machine that has the package and the signing key's `kid` (printed in the summary, and by `verify_receipt`):

```bash
trust-gate-artex verify --chain /srv/example/artex-receipts --kid <kid>                # every finding, every link
trust-gate-artex verify 000001.receipt.json 000001.record.json --kid <kid>             # one pair
```

`verify` checks the signature, that the signer is the pinned `kid`, that the receipt was issued by this bridge (and not by
`mint_action_receipt` with look-alike fields), that the record hashes to the signed `inputs_hash`, that sequence numbers are
contiguous and linked by `previous_inputs_hash`, and that the instance and ARTEX address did not change (unless you pass
`--allow-origin-change`). A receipt more than an hour older than its observation time is flagged `time_gap_flag`.
Design and review record: [docs/designs/artex_sync.md](./designs/artex_sync.md).
