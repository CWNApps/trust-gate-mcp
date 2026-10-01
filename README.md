# Trust Gate MCP

Tamper-evident receipts for consequential agent actions, as an MCP server, with a decision gate that returns ALLOW, DENY or ESCALATE.

Seven tools, one shared signing primitive: the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) `mint_receipt`.

**What actually gets signed depends on what you install** -- OAO detects its backend at import time, so this is worth stating plainly rather than advertising the best case:

| Install | Legs | Notes |
|---|---|---|
| `pip install trust-gate-mcp` | Ed25519 + ML-DSA-65 | Default. The ML-DSA leg comes from `dilithium-py`, a pure-Python library whose own README says it must not be used for cryptographic applications and that it is not constant-time. It keeps receipts tamper-evident and satisfies PQ-required mode, but treat that leg as unhardened. |
| `pip install "trust-gate-mcp[slh]"` | Ed25519 + ML-DSA-65 (native backend) | Installs `liboqs-python`, which needs the native liboqs library; the signing primitive then prefers liboqs for ML-DSA-65. It adds a hash-based leg only if that liboqs still ships `SPHINCS+-SHA2-128s-simple` (a pre-standard variant, not byte-compatible with the final FIPS 205 standard). liboqs 0.16.0, the only release `liboqs-python` currently targets, removed SPHINCS+, so as of 2026-09-29 this extra gives the native ML-DSA backend and no hash-based leg (not verified with liboqs installed). If liboqs cannot be imported the primitive silently falls back to `dilithium-py`; `run_exit_drill` names the active backend and whether the hash-based leg is available. Use this install if the post-quantum legs matter to you. |

PQ-required verify (the default) demands **at least one** verified post-quantum leg. That shows a post-quantum signature is present and valid over the same bytes. It does not say whose key made it (see "What a valid receipt proves"), and it does not make the default backend production-grade.

| Tool | What it does |
|---|---|
| `mint_receipt_for_record_change` | Mints a receipt for a CRM record change. Works with any CRM (open-core Relaticle, hosted CRMs via their own MCP, custom). Old/new values are SHA-256 hashes (unsalted, so a low-entropy value can be guessed from its hash). |
| `audit_my_agent_inventory` | Ranks a CALLER-PROVIDED list of MCP tools by worst-regret if they act (a name-based heuristic that weights a name's first word most: `delete_file` ranks above `file_delete`). **Read-only: it mints no receipt.** Cannot auto-discover other servers -- MCP protocol does not allow that. A row that is not an object is an error, never silently skipped. |
| `mint_action_receipt` | Receipt for any consequential agent action. Attestation values (`triggered_by_*`, `decision_model`) are caller claims: limited to safe characters, signed, not verified. Decision values that contain a gate verdict word (allow, deny, escalate, grant, permit, approve, withheld, committed), operation names with `gate` as a word, and the gate's own policy id are refused. That check is best effort: to tell a gate verdict from anything else, check the signed `issuer_tool` (see below). |
| `verify_receipt` | Verify a receipt from the certificate alone -- offline, no DB. Refuses unsigned receipts, checks the `kid`, and accepts `expected_kid` to pin the signer (counted only when that key's own Ed25519 signature verifies). Defaults to PQ-required mode. When it says ok it returns a `verified` block (decision, evidence hash, signed time, `issuer_tool`, `operation` and the whole verified `ontology` manifest, including the action and resource): read those values, not your own parse of the receipt. |
| `gate_decision` | Two-phase decision gate with a real verdict. PREVIEW returns ALLOW, DENY or ESCALATE with the risk tier and reasons, without acting. COMMIT re-evaluates and mints a signed receipt for the verdict. Only ALLOW returns a `GRANTED` permit; DENY returns `DENIED`; ESCALATE returns `WITHHELD_PENDING_HUMAN` and a human decides. See below. |
| `check_egress` | Flags sensitive markers in a data sample (a finite list of keywords, SSN and card-number shapes, and common credential formats, including `NAME=value` assignments) as NO_MARKERS_FOUND / INTERNAL / CONFIDENTIAL / RESTRICTED. Credential-shaped values and personal identifiers are RESTRICTED and set `blocked: true`; credential keywords alone are CONFIDENTIAL. A harmless sample that looks like an assignment of a key or password can be flagged too. **It cannot block anything itself**: your code must read `blocked` and obey it. NO_MARKERS_FOUND is not clearance to send. Returns classification + retention info + receipt. |
| `run_exit_drill` | Vendor exit readiness drill. Checks the local signing key (names the post-quantum backend and whether the hash-based leg is available) and that a local model endpoint is configured (Ollama; it is not contacted, and a remote host is not counted). Returns step-by-step results + receipt. Informational; it signs one receipt, which creates the signing key on a host that has none yet. |

## What the gate does and does not do

* **Scope.** It applies only to actions your code routes through `gate_decision`. It does not observe, intercept or block anything an agent does, and it does not check afterward whether an action happened. Your code (a hook, a wrapper) must ask first and must obey the answer.
* **ALLOW is a closed list.** An action gets ALLOW only when its name is a known read verb (`read`, `get`, `list`, `search`, `query`, `find`, `show`, `view`, `inspect`, `describe`) followed only by words from a small built-in vocabulary of nouns (for example `read_file`, `list_files`, `search_files`, `list_dir`, `get_user`, `describe_table`), the name is a plain identifier, and the resource is built only from words of that vocabulary, a few ordinary document words (`readme`, `guide`, `changelog`, ...) and source or prose file types (`md`, `txt`, `py`, ...), with digits allowed between words (`docs/2024/notes.md`). A name that contains any other word escalates to a human, because the gate has not seen it. **This is deliberately narrow: most real file names escalate.** Widening it means adding words to the vocabulary in the source, which is a visible change.
* **Structural rules escalate as well.** A hidden path (`.env`, `.ssh`, `.git`, `..`), an absolute path, a URL, a host name as the first part of a path (`example.com/x`, `localhost`), a network address in any of its usual spellings (four dotted numbers of any width, hexadecimal, octal such as `0177.1`, one long integer, `0`; short dotted numbers such as `1.2.3` stay versions unless the last number is too large for a version or the first is `0` or `127`), a resource that starts with `-`, a phrase of three or more words, anything containing characters other than letters, digits, spaces and `_ . - /`, and a file whose real type is configuration, data, key, state or archive (a rotation counter such as `.1` is ignored when judging the type; a listed data or archive type earlier in a dotted name, such as `users.csv.txt`, counts too). A resource that carries a command escalates: a listed mutating word (`alter`, `merge`, `flush`, `load`, ...), a critical verb glued to a word (`deleteall`), or any multi-word resource after a `query` verb.
* **DENY is for a critical lead verb** (payments, deletion, deployment, code execution, privilege changes). A risky word elsewhere in the name, or in the resource, escalates so that a human decides; so do the high-risk lead verbs (`format`, `remove`, `reset`, `release`, `escalate`) and a file name that contains a risky word (`test_delete_user.py`).
* **Risky and sensitive words are listed, and the lists are finite.** Listed secret and regulated-data words (password, token, key, pass, config, ssn, diagnosis, ... in their glued, plural and digit-swapped forms) give the HIGH tier a specific reason. The lists are not what keeps a name from being allowed (a sensitive name on no list still escalates, because ALLOW is closed). `history` is not a read noun. Matching runs across word boundaries, so some harmless names show the sensitive reason (`api/index.md` contains "pii"). A lookup such as `list_users` is a read like any other: the gate does not judge how much personal data it returns. Common read tools whose names contain a word that is also a risky verb (`get_email`, `list_messages`) escalate.
* **It is a name-based heuristic, not a proof.** ALLOW does not mean the action is safe: an agent that calls a dangerous tool `read_file` is not caught, because the gate sees names, not behaviour. `context` is recorded in the receipt as a hash and is not used to decide. There is no operator override in this package.
* **Read the verdict from the receipt, and check who issued it.** `receipt.decision` (and `receipt.evidence.ontology.verdict`) are signed. The top-level `verdict` and `permit` fields of the response are not; `verify_receipt` lists the unsigned keys of any receipt it checks. A receipt is a gate verdict only if its signed manifest says `issuer_tool: gate_decision` and `operation: decision_gate_commit`; every other tool signs its own `issuer_tool`.
* **No permit without a receipt this server would accept.** COMMIT issues `GRANTED` only if the receipt was minted and signed, and verifies under this server's own policy (in PQ-required mode that includes a valid post-quantum signature).
* **Action and resource are recorded in clear text** in the signed receipt. Do not put secrets or personal data in them.
* **A receipt is evidence of a verdict, not a log entry.** `atom_id` is derived from the content (40 bits of the evidence hash), so identical decisions share one and different decisions can too; key on `evidence_hash` and `signed_at`. The server keeps no log of the receipts it signs: store the ones you need. There is no replay or freshness check: compare `evidence.ontology.action` and `resource` with what you are about to do.
* **0.2.1 returned `GRANTED` for every action.** Upgrade to 0.3.0. See the [changelog](./CHANGELOG.md).

## What a valid receipt proves

`verify_receipt` returning `ok: true` means the evidence is unchanged since it was signed, the receipt carries a signature, any `kid` it carries matches the key it carries, and (in the default PQ-required mode) at least one post-quantum signature verified over the same bytes.

It does **not** mean the receipt came from a server you trust: anyone can generate keys and sign a receipt. To check *who* signed, pass `expected_kid` (the `kid` of the Ed25519 key you trust, learned out of band; 32 hexadecimal characters, case and surrounding spaces ignored, a blank or malformed pin is refused). A pin counts only when that key's own Ed25519 signature verifies, and `signer_pinned: true` says it did (a signature verifying shows that the key signed those bytes, not that anyone holds its private key: Ed25519 accepts a few special public keys that verify for any message, which cannot affect a pin on a key you trust); `ok: true` with `signer_pinned: false` is an integrity result only, and `kid` is reported only when the Ed25519 signature verified. A receipt that names an Ed25519 signer (key or `kid`) without a valid signature from it is refused: those two values are public and can be copied into a receipt signed with other keys.

On stdio the signing key is stored unencrypted under the user's home directory, so an agent running as that user can read it: a pin does not protect against the agent you are gating. The `kid` fingerprints the Ed25519 key only. The ML-DSA and hash-based keys inside a receipt are not covered by it, so a pinned check is only as strong against a quantum attacker as Ed25519. Results can also depend on which post-quantum backends the verifying host has installed (a leg it cannot check is reported `unverifiable`).

## Hardening

* **H1** key persistence + bootstrap with FAIL-CLOSED `kid`-drift check (container deploy; the bootstrap checks the Ed25519 key only)
* **H2** per-IP token-bucket rate limit (FIFO eviction). It parses the request body exactly as the MCP transport does, from the raw bytes (a byte-order mark, UTF-16 and UTF-32 are read too), and charges the tool it names; the signing tools share the signing budget. A body it cannot parse, or one over 64 KiB, is charged to the signing budget; a request is refused with 413 as soon as its body exceeds 1 MiB (at most 1 MiB is buffered). Signing (about 70 ms per call with the default backend) and verification (about 20 ms) run on the event loop and the budgets are per client, so there is no overall cap on that work. Clients are identified by the connection address as uvicorn resolves it: set `TRUST_GATE_FORWARDED_ALLOW_IPS` to your proxy's address, or any client can choose its own identity with an `X-Forwarded-For` header.
* **H3** PQ-required verify: refuses a receipt with no verified post-quantum signature (and any unsigned receipt)
* **H4** 128-bit `kid` on every minted receipt, recomputed from the canonical key bytes and checked on verify
* Optional bearer auth and a narrowed CORS allowlist via `TRUST_GATE_BEARER_TOKEN` + `TRUST_GATE_ALLOWED_ORIGINS`
* The test suite pins every listed verb, noun and sensitive word individually (from an independent copy of the lists) and tests their inflected, plural, glued, digit-swapped and compatibility-character forms, plus adversarial cases for receipt forgery and PQ stripping; real MCP requests are posted through the whole HTTP stack

## Deploying over HTTP

The HTTP entrypoint (`server_http.py`) is written for the container image, where its modules sit side by side; with a `pip install`, use the stdio server. Bearer auth is **off** by default and CORS is `*` in that mode. Anyone who can reach an open deployment can obtain receipts signed with its key, including "ALLOW" receipts for read-only names, and a receipt from an open deployment says nothing about who asked. If you host it, set `TRUST_GATE_BEARER_TOKEN` and `TRUST_GATE_ALLOWED_ORIGINS`.

The HTTP entrypoint counts `?via=<label>` visits as one log line (label, kind, user-agent family). Only three built-in labels plus those named in `TRUST_GATE_CHANNELS` (comma separated) are recorded; the host's own access log also records request lines, including client addresses.

DNS-rebinding protection is off and there is no switch for it: on a local HTTP server without bearer auth, any web page you visit can call it. Put it behind a proxy that checks the Host header, or set `TRUST_GATE_BEARER_TOKEN`.

## Install (stdio)

```bash
pip install trust-gate-mcp
trust-gate-mcp
```

Add `[slh]` for the native ML-DSA backend (see the table above). From a checkout, `pip install -e ".[dev]"` then
`python -m trust_gate_mcp`.

## Container deploy (Smithery / any container host)

```bash
docker build -t trust-gate-mcp .
docker run -p 8081:8081 -v trust-gate-data:/data/oao trust-gate-mcp
```

The volume mount on `/data/oao` is **required for production**: without it the signing key changes on every container restart, receipts signed before a restart still verify from their own certificate, but a pinned `kid` stops matching new ones. The persistent `key_metadata.json` holds the signer's `kid`; the bootstrap step refuses to start if it drifts. The image installs `dilithium-py` by default; see the table above.

## License

Apache-2.0. Built on the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology) primitive.
