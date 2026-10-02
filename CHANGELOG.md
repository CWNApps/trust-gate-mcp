# Changelog

## 0.3.0 -- 2026-09-29

**SECURITY FIX: `gate_decision` now returns a real verdict, and ALLOW has to be earned.**

In 0.2.1, `gate_decision` at `phase="COMMIT"` returned `"permit": "GRANTED"` for every input, including
critical actions such as "wire funds", and signed a receipt whose decision was always `DECISION_COMMITTED`.
There was no deny path and no escalate path. Any agent or client that treated the GRANTED permit as an
approval was approved for everything. This self-contained `gate_decision` first appeared in the source on
2026-07-13 (0.1.0 had a tool of the same name that called a hosted backend and does not contain this code).
0.2.0 was never released (no tag, no PyPI upload), so 0.2.1 is the only PyPI release with the defect.

**Affected:** 0.2.1 on PyPI; the container image built from that release (GHCR tag `v0.2.1`; the `latest`
tag pointed at the same image digest when checked on 2026-09-29, so re-pull once 0.3.0 is published); anything
else built from `main` after 2026-07-13. The hosted demo instance at trust-gate-mcp.onrender.com was serving an older build (0.2.0, four
tools, no `gate_decision`) when checked on 2026-09-29: it does not have this defect, but it has the other
problems fixed here (a stale server card, an unrestricted `mint_action_receipt`) until it is redeployed. The
framework wrapper packages `cwn-langchain-trust-gate`, `cwn-crewai-trust-gate` and `cwn-llama-index-trust-gate`
may call `gate_decision` on a Trust Gate MCP server: if you use one, treat any GRANTED result from a
pre-0.3.0 server as not evidence.
**Not affected:** 0.1.0 does not contain this code (its `gate_decision` called a hosted backend, which this
release does not cover). **Action:** upgrade to 0.3.0 and re-test any workflow that relied on a GRANTED permit:
it is now issued only for the read-only names described below. See "Upgrading" for receipts and keys.

### The gate
- Verdicts: `ALLOW`, `DENY`, `ESCALATE`. Permits: `GRANTED` only for ALLOW, `DENIED` for DENY,
  `WITHHELD_PENDING_HUMAN` for ESCALATE, and `NOT_ISSUED` unless the receipt was minted, signed and verifies
  under this server's own policy (so, while PQ-required mode is on, it carries a valid post-quantum signature).
  COMMIT evaluates the inputs again and never reads a verdict from the caller. The receipt's `decision` is
  the verdict.
- ALLOW is a closed list. An action is allowed only if its name is a known read verb (read, get, list, search,
  query, find, show, view, inspect, describe, in their listed forms) followed only by words from a small built-in
  vocabulary of nouns (file, table, user, order and similar) or digits, and the resource is built only from words
  of that vocabulary, a few ordinary document words (readme, guide, changelog and similar) and source or prose
  file types (`md`, `txt`, `py` and similar), with digits allowed between words (`docs/2024/notes.md`). A name
  that contains any other word escalates to a human, because the gate has not seen it. This is deliberately
  narrow: most real file names escalate. Widening it means adding words to the vocabulary in the source, which is
  a visible change. The listed read-verb forms are written out one by one.
- Structural rules escalate as well: an absolute path, a hidden path (`.env`, `.ssh`,
  `.git`), a parent-directory path, a URL, a host name as the first part of a path (`example.com/x`), a network
  address in any of its usual spellings (four dotted numbers of any width, hexadecimal, octal such as `0177.1`,
  one long integer, `0`, `localhost` and the other loopback names; short dotted numbers such as `1.2.3` stay
  versions unless the last number is too large for a version or the first is `0` or `127`), a resource that
  starts with `-`, a phrase of three or more words, characters other than letters, digits, spaces and
  `_ . - /` (after Unicode compatibility folding), and a file whose real type is configuration, data, keys,
  state or an archive. The real type is the
  last extension that is not a rotation or version counter (`app.log.1` is `.log`); a listed data or archive type
  earlier in a dotted name (`users.csv.txt`) counts as well. The last real path segment is judged and every
  segment is trimmed of whitespace first, so a trailing separator, `/./` or a stray space hides nothing.
- A resource that carries a command escalates: a listed mutating word (`alter`, `merge`, `flush`, `load`,
  `mount` and similar), a CRITICAL verb glued to the front of a word (`deleteall`, `dropdb`), or, after a
  `query` verb, any multi-word resource.
- DENY is for a critical LEAD verb (payments, deletion, deployment, code execution, privilege changes). A risky
  word elsewhere in the name, or anywhere in the resource, ESCALATEs so that a human decides, as do the
  high-risk lead verbs (`format`, `remove`, `reset`, `release`, `escalate`); `list_payments` and
  `test_delete_user.py` are not hard-denied.
- Listed secret and regulated-data words (password, token, key, pass, config, ssn, diagnosis and similar, in
  their glued, plural and digit-swapped forms) give the HIGH tier a specific reason. The lists are finite and
  are not what keeps a name from being allowed: a sensitive name on no list still escalates, because ALLOW is
  closed. `history` is not a read noun (it records what a person did). Matching runs across word boundaries, so
  some harmless names show the sensitive reason (`api/index.md` contains "pii").
- Input limits: action and resource at most 512 characters, context at most 65,536 serialised. Blank, non-text
  and lone-surrogate inputs are refused with a structured error.

### Receipts
- `verify_receipt` refuses a receipt that carries no signature (before, it returned ok=true, "UNSIGNED"),
  checks the receipt's `kid` against the key it carries, and lists `unsigned_top_level_keys`: read the verdict
  from `decision`, never from top-level keys that are not signed. Its `reason` and `signature_alg` are
  derived from the signatures that verified, not copied from the receipt.
- A receipt that names an Ed25519 signer (a public key or a `kid`) but carries no valid signature from that key
  is refused, whatever other signatures it carries: the key and the `kid` are public and can be copied into a
  receipt signed with other keys. A receipt that names no Ed25519 signer at all still verifies as integrity only,
  reports no `kid` and can never satisfy a pin.
- `expected_kid` pins the signer. It must be 32 hexadecimal characters (case and surrounding spaces are ignored; a blank or malformed pin is refused)
  and counts only when that key's own Ed25519 signature verifies; `signer_pinned` is true only then. `kid` is
  reported only when the Ed25519 signature verified, and a receipt whose Ed25519 key is spelled with a stray
  character is refused. A receipt cannot borrow another receipt's key or kid: those are public, and a signature from some other key does not stand in for them. The `kid` is computed from the canonical bytes of the key.
- The post-quantum keys inside a receipt are not covered by the `kid`. PQ-required mode shows that a
  post-quantum signature is present and valid, not whose it is, and a pinned check is only as strong against a
  quantum attacker as Ed25519.
- Every receipt's `note_pq` field (unsigned) now says that, and says "Ed25519 signature only" when no
  post-quantum signature was produced; the signing primitive's own wording claimed that any one valid leg proves
  authenticity.
- When `verify_receipt` says ok it also returns a `verified` block (decision, evidence hash, signed time,
  `issuer_tool`, `operation`): read those values rather than your own parse of the receipt.
- `mint_action_receipt` refuses decision values that contain a gate verdict word (allow, deny, escalate, grant,
  permit, approve, withheld, committed; also with digits or symbols swapped in, such as `ALL0W` or `gr@nted`),
  operation names with `gate` as a word (also digit-swapped) or containing both "decision" and "gate", the gate's own policy id, and non-printable-ASCII text. This is best effort and
  is not the trust boundary: every tool signs an `issuer_tool` field into its manifest, and a gate verdict is
  one whose manifest says `issuer_tool: gate_decision` and `operation: decision_gate_commit` AND whose signer you
  have pinned (`expected_kid` with `signer_pinned: true`); without the pin those fields are claims made by
  whoever signed. This is breaking
  for anyone who used those decision values.
- `TRUST_GATE_REQUIRE_PQ` fails closed: only `0`, `false`, `no` or `off` turn PQ-required mode off (and
  `OAO_REQUIRE_PQ` does the same when `TRUST_GATE_REQUIRE_PQ` is empty).
- Attestation values are checked with a full match (a trailing newline no longer passes). They are caller
  claims: signed, in clear text, limited by character class only, not verified.
- `preview_id` encodes its inputs unambiguously. A receipt body larger than 262,144 characters is refused, and
  a lone surrogate in any tool's input is hashed instead of raising.

### Other tools
- `check_egress`: the all-clear label `PUBLIC` is now `NO_MARKERS_FOUND` (breaking), because it never meant
  the data was safe to send. A finite list of credential formats (cloud keys, access tokens, private keys,
  JWTs, passwords in URLs, bearer tokens, `NAME=value` assignments whose name ends in a credential word, in any
  letter case) and personal-identifier shapes (SSN, Luhn-checked card numbers, also when another digit group such as a CVV or
  an expiry sits next to them) is RESTRICTED and sets
  `blocked: true`; credential keywords alone are CONFIDENTIAL; keywords match inside `SNAKE_CASE` names. The
  `provider` field is scanned and limited to 200 characters, and is withheld from the response and the receipt
  when it would be RESTRICTED. Input is limited to 65,536 characters and scanned in linear time. The tool flags
  a finite list of markers and cannot block anything itself; a harmless sample that looks like an assignment
  of a key or password can be flagged too.
- `audit_my_agent_inventory` returns an error for a row that is not an object instead of skipping it. It
  weights a tool name's first word most (`delete_file` ranks above `file_delete`).
- `run_exit_drill` has two checks now (the local signing key and a local model endpoint); the third only
  asserted a constant. It names the active post-quantum backend, reports whether the hash-based leg is
  available, reports the signing step as `WARN` (readiness `PARTIAL`) on the pure-Python backend and as `FAIL`
  when this host could not sign its own receipt, counts a model endpoint only if it is configured and local (it
  is not contacted), and reports only the scheme, host and port of `OLLAMA_HOST` (no credentials, path or query). It signs
  a receipt, so on a host with no signing key yet it creates one.
- A failure to sign returns an opaque `mint_failed` error instead of an exception message that could carry a
  file path.

### HTTP entrypoint
- The server card and landing page are built from the running server, so the version and tool list cannot drift
  (they had said "0.2.0, four tools"). `build_app()` builds the whole application, and tests post real MCP
  requests (`initialize`, `tools/list`, `tools/call`) through the whole middleware stack.
- The rate limiter is plain ASGI middleware: it buffers the body to classify it and to enforce the size cap, then
  hands the same body to the application. It parses the body exactly as the MCP transport does, from the raw
  bytes (a byte-order mark, UTF-16 and UTF-32 are read too), and charges the tool it names; `gate_decision`,
  `check_egress` and `run_exit_drill` share the signing budget. A body it cannot parse, or one over 64 KiB, is
  charged to the signing budget. A request is refused with 413 as soon as its body exceeds 1 MiB (at most 1 MiB
  is buffered). Signing runs on the event loop (about 70 ms per call with the default backend), and the budgets
  are per client: there is no overall cap on signing work. Clients are identified by the connection address as
  resolved by uvicorn; set `TRUST_GATE_FORWARDED_ALLOW_IPS` to your proxy's address, or any client can choose its
  own identity with an `X-Forwarded-For` header (the default remains any proxy, for hosts behind an unknown
  proxy).
- A bearer token with non-ASCII characters is rejected with 401 (it raised a 500).
- The attribution counter records three built-in labels plus those named in `TRUST_GATE_CHANNELS`.
- Removed the development fallback that searched for a sibling checkout of the signing primitive.

### Packaging
- The source distribution is now an allowlist: the package, README, changelog, licence and build file.
  Before, it included every file tracked in the repository. A test builds the sdist and checks its file list.
- The container image installs the signing primitive from PyPI with a version bound instead of a moving branch,
  and `mcp` is bounded at `>=1.12,<2`.
- A `tests.yml` workflow runs the suite on pushes to `main` and on every pull request, and the container
  publish workflow now runs the suite before pushing an image (the PyPI workflow already did). Removed four
  maintainer files that did not belong in a public package (`PUBLISH.md`, `publish.sh`, `demo.html`,
  `gen_demo.py`) and the `client.py` and `config.py` modules of the 0.1.0 hosted-backend client, which nothing
  in the package used (**breaking** for anyone who imported them). `httpx` is no longer a runtime dependency
  (it is a test dependency). `server.json` lists no remote until the hosted instance serves this release.

### Documentation
- Removed claims the code did not support: SLH-DSA as a default leg, "no server to trust", compliance-framework
  lists, "audit_my_agent_inventory ... with a signed receipt" (it mints nothing), "blocks RESTRICTED",
  "never stored in the clear", "defeats signature stripping" and
  "survives a lattice break". Removed wording that did not belong in public files, and added a test that fails on drive-letter and
  home-directory paths and personal mail domains.
- Stated plainly what the default install signs with: `pip install trust-gate-mcp` gets its ML-DSA-65 leg from
  `dilithium-py`, a pure-Python library whose own README says it must not be used for cryptographic
  applications and that it is not constant-time. That leg keeps receipts tamper-evident and satisfies
  PQ-required mode, but treat it as unhardened. `pip install "trust-gate-mcp[slh]"` installs `liboqs-python`,
  which needs the native liboqs library and is preferred by the signing primitive for ML-DSA-65. The
  hash-based leg needs a liboqs that still ships `SPHINCS+-SHA2-128s-simple` (a pre-standard variant, not
  byte-compatible with the final FIPS 205 standard); liboqs 0.16.0, the only release `liboqs-python` currently
  targets, removed SPHINCS+ (per its release notes), so today this extra gives the native ML-DSA backend and no
  hash-based leg. Not verified with liboqs installed. If liboqs cannot be imported the primitive silently falls
  back to `dilithium-py`; `run_exit_drill` names the active backend and whether the hash-based leg is available.

### Upgrading
- Receipts made before 0.3.0 have no `issuer_tool`. Treat none of them as a gate verdict: on a deployment that
  ran 0.2.x without bearer auth, anyone could have minted a receipt with decision `ALLOW` through
  `mint_action_receipt`. Rotate the signing key when you upgrade and pin the new `kid` (old receipts still verify
  from their own certificate, but a pin on the old `kid` will not match new ones). To rotate: stop the server,
  move `receipt_ed25519.pem`, its `.mldsa.pk` / `.mldsa.sk` companion files (and any `.slhdsa.pk` / `.slhdsa.sk`) and `key_metadata.json` out of the
  key directory (keep them, do not delete), and start it again; a new key and metadata are written on first start.
  The bootstrap refuses to start with exit code 78 if the metadata names a different key than the one in use.
- If you host over HTTP, set `TRUST_GATE_BEARER_TOKEN`, `TRUST_GATE_ALLOWED_ORIGINS` and
  `TRUST_GATE_FORWARDED_ALLOW_IPS`.

### What this does not change
- The verdict applies only to actions your code routes through the gate. This package does not observe,
  intercept or block anything an agent does, and does not check afterward whether an action happened.
- The gate judges names, not behaviour. A dangerous tool named `read_file` is not caught.
- A valid receipt proves that whoever holds the embedded key(s) signed those bytes; pin the Ed25519 `kid` to
  know it is a key you trust. Receipts are tamper-evident, not proof of compliance. There is no replay or
  freshness check.
- HTTP exposure is unchanged where not listed above: bearer auth is off by default and CORS is `*` in that mode,
  so anyone who can reach an open deployment can obtain signed receipts. DNS-rebinding protection is off
  (there is no switch for it), so on a local HTTP server without bearer auth any web page you visit can call
  it: put it behind a proxy that checks the Host header, or turn bearer auth on.
- The signing primitive stores its keys unencrypted under `~/.openagentontology/` (or `OAO_RECEIPT_KEY`). The
  gate escalates a read of them by name or file type, but it cannot stop an agent that reads them without asking.
- The gate's action and resource are recorded in clear text in the signed receipt.
- `atom_id` is derived from the receipt's content (40 bits of the evidence hash), so identical decisions share
  one and different decisions can too; key on `evidence_hash`. The server keeps no log of the receipts it signs.
- The mint tools other than `gate_decision` do not cap the size of their text inputs beyond the 262,144
  character body limit and the 1 MiB request limit.

*Entries below 0.3.0 are historical and keep their original wording; several claims in them ("blocks RESTRICTED", "defeats signature-stripping", "33/33", "a PII guard, so a free-text field can never smuggle personal data", "mints post-quantum receipts", "same-notary check", "DoS-hardened") were withdrawn, see the 0.3.0 Documentation section.*

## 0.2.1 -- 2026-07-29 (the changes below were committed on 2026-07-13)

**Attestation provenance.** `mint_action_receipt` and `gate_decision` now accept three
optional fields that answer "who/what set this action in motion" and get signed into the
receipt manifest when supplied:

- `triggered_by_type` -- human / agent / script
- `triggered_by_source` -- api / cli / cron
- `decision_model` -- the LLM model behind the decision

Values are allowlisted to `[A-Za-z0-9._-/]`, max 80 chars, and silently dropped if they
fail the check -- a PII guard, so a free-text field can never smuggle personal data into
a signed, immutable receipt. Omitting the fields leaves the manifest exactly as in 0.2.0,
so existing receipts and verifiers are unaffected.

Also adds the GitHub Actions Trusted Publishing workflow (`publish-pypi.yml`) that
releases this package to PyPI on `release: published`.

## 0.2.0 -- 2026-06-25 (never released to PyPI; the gate, egress and exit-drill tools below were added on 2026-07-13)

**Architecture change.** Trust Gate MCP evolves from a thin client of the hosted
`cwn-trust-gate.onrender.com` backend into a SELF-CONTAINED MCP server that mints
post-quantum receipts locally via the open-source [OpenAgentOntology](https://github.com/CWNApps/openagentontology)
primitive. No hosted backend dependency.

### Tools (full set rewritten)
- `mint_receipt_for_record_change(...)` -- tamper-evident per-change receipt for any CRM
- `audit_my_agent_inventory(inventory)` -- worst-regret ranking of a CALLER-PROVIDED list (READ-ONLY)
- `mint_action_receipt(...)` -- general-purpose consequential-action receipt
- `verify_receipt(receipt)` -- offline verify from the certificate alone

### Sovereignty Tools (new)
- `gate_decision(action, resource, context, phase)` -- two-phase PREVIEW->COMMIT decision gate; PREVIEW returns risk assessment + preview_id, COMMIT verifies inputs + mints receipt
- `check_egress(destination, data_sample, provider)` -- egress data-sensitivity classification (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED); blocks RESTRICTED; receipt per classification
- `run_exit_drill()` -- vendor exit readiness check (local signing, local model, local data export); informational + receipt

The v0.1.0 tools (`gate_decision`, `check_policy`, `health`) are removed from the MCP
surface. The `client.py` + `config.py` modules are kept under `src/trust_gate_mcp/` for
callers that still want to talk to the hosted backend; `build_server()` does not use them.

### Hardening
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
