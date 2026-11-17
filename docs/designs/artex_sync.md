# Design: `trust-gate-artex` (ARTEX findings to signed receipts)

Status: v3.1, revised after goldfish rounds 1, 2 and 3 (2026-11-17); round 3 was the last, its findings are fixed below and logged at the end.

Terms: OAO = OpenAgentOntology (the signing library trust-gate-mcp uses); kid = key id (a short hash of the Ed25519 public key); PQ = post-quantum (ML-DSA-65); head = a finding's latest receipt.

## 1. Goal

A customer runs [ARTEX](https://github.com/BaaRai/ARTEX) (a self-hosted autonomous penetration testing platform, AGPL-3.0, a separate
project; only v0.6.0, commit `a13c68cb`, was reviewed) on their own network. ARTEX stores each finding with the HTTP request and
response bodies that back it. This tool gives each finding a signed receipt from the customer's own trust-gate-mcp signing key,
so a third party can later check that **the key holder saw this ARTEX API return this finding, with these evidence-body hashes,
at about this time**, and that the record was not edited afterwards. Target data never leaves the customer's network: the
receipt carries hashes and ids, not content.

Asked for by Spectre (2026-11-17) as the customer-facing "pentest findings with receipts" piece. Customers run ARTEX themselves
(decision of the same day); CWN does not host it. What a receipt does **not** say is in section 7.

## 2. How the existing pieces work

- **trust-gate-mcp** signs through one primitive, `_mint(manifest, decision)` in `server.py`, which calls OpenAgentOntology
  `mint_receipt`. The whole manifest becomes `receipt.evidence.ontology`, covered by `evidence_hash` and every signature leg
  (Ed25519, plus ML-DSA-65 when the post-quantum backend is installed). `_mint` passes no key path: OAO reads
  `OAO_RECEIPT_KEY` **once, when it is imported**, and falls back to a key in the user's home directory, creating it if absent.
  Without `cryptography` OAO returns an unsigned receipt (`signed: false`, `alg: "none"`) instead of failing; `_mint` returns an
  `{"error": ...}` dict for `openagentontology_unavailable`, `mint_failed`, `manifest_too_large`.
  `_ascii_hash(s)` is `"sha256:" + hex` of `s.encode("utf-8","surrogatepass")`. `_verify(receipt, require_pq, expected_kid)` returns
  `ok`, `signer_pinned`, and `verified` (including `issuer_tool`, `operation`, and `ontology`, the signed manifest).
  `require_pq` defaults to ON via `TRUST_GATE_REQUIRE_PQ` / `OAO_REQUIRE_PQ`, so a host without a post-quantum backend mints
  receipts that default verification rejects.
- **ARTEX REST API** (v0.6.0): one fixed admin account, one JWT type (HS256, 7 days), no scoped tokens.
  - `POST /api/auth/login` `{"username","password"}` returns `{"token"}`; 10 attempts per minute per IP, then longer blocks.
  - `GET /api/health` with the token returns `{"service","version"}`.
  - `GET /api/exploration/findings?page=N&limit=200` returns `{items,total,page,page_size}`, newest first.
  - `GET /api/exploration/findings/{id}` returns one finding. Many keys are omitted when empty (`name`, `task_id`, `report`,
    `assets`, `counterevidence`, `confidence_rationale`). It carries `traffic_count` but NOT the bindings (found in the live
    run against v0.6.0, 2026-11-17; the DTO has a `traffic_bindings` field that the detail endpoint leaves empty).
  - `GET /api/exploration/findings/{id}/traffic` returns `{finding_id, version, bindings: [...]}`. The bridge reads it after the
    detail and fails the finding with `evidence_changed` if `version` differs from the detail's `evidence_version` or the
    binding count differs from `traffic_count` (the evidence moved between the two requests).
  - A traffic binding (`id`, `role`, `note`, `position`, `created_at`) holds a `snapshot` (`id`, `method`, `url`, `status`,
    `captured_at`, `req_hash`, `resp_hash` as sha256 hex, `req_len`, `resp_len`).
  - `GET /api/exploration/findings/{id}/traffic/{binding_id}/body?side=request|response&download=1` streams one body; ARTEX
    re-checks the stored blob against its hash and length first.

## 3. Shape

A separate console script `trust-gate-artex` (`[project.scripts]`), implemented in `src/trust_gate_mcp/artex_sync.py`. It does not
touch `main()` of the MCP server, is not copied into the container image, and runs on the host or in a customer job next to
ARTEX. `sync` is POSIX only (it uses `fcntl.flock`, imported lazily; on Windows it exits 3 with a message); `verify` runs anywhere.

```
trust-gate-artex sync   --out DIR --instance-name NAME [--max-body-bytes N] [--verify-bodies] [--init-key]
                        [--allow-insecure] [--rebind] [--ack-gone KEY]...
trust-gate-artex verify RECEIPT RECORD --kid KID [--require-pq | --no-require-pq]
trust-gate-artex verify --chain DIR --kid KID [--allow-origin-change] [--require-pq | --no-require-pq]
```

Environment: `ARTEX_URL` (default `http://127.0.0.1:8787`), `ARTEX_USERNAME`, `ARTEX_PASSWORD` (or `ARTEX_PASSWORD_FILE`),
`OAO_RECEIPT_KEY` (required). Credentials are never accepted as arguments. `OUT` must be on a local disk (flock is not reliable
on network or synced drives).

Exit codes, `sync`: 0 all good; 1 finished with failures, `finding_gone` or an incomplete listing; 2 usage error (argparse); 3
pre-flight refused (lock held, key unset or missing or not the one OAO loaded, instance mismatch, insecure URL, no
`openagentontology`, not POSIX). `verify`: 0 pass; 1 fail; 2 usage error (including a missing `--kid`: it is required, so an
unpinned verify cannot be run by accident).

### 3.1 Module surface

```python
def main(argv: list[str] | None = None) -> int
def build_record(detail: dict, bodies: dict[tuple[str, str], tuple[str, int]]) -> str   # canonical ASCII JSON string;
                                                                          # bodies[(binding_id, "request"|"response")] = (sha256 hex, length)
def record_hash(record: str) -> str                                  # _ascii_hash(record), "sha256:<hex>"
def sync(client, out: Path, instance_name: str, opts: Options) -> Summary
def mint_finding(record: str, key: str, seq: int, previous: str | None, meta: RunMeta) -> dict   # the receipt
def load_head(findings_dir: Path, key: str) -> Head | None           # latest verified (seq, record, receipt) or raises ReceiptInvalid
def verify_pair(receipt: dict, record_bytes: bytes, kid: str, require_pq: bool | None) -> VerifyResult
def verify_chain(out: Path, kid: str, ...) -> ChainResult
```

`Options`, `Summary`, `Head`, `RunMeta`, `VerifyResult` are small frozen dataclasses holding exactly the fields named in this document.
It imports `_mint`, `_verify`, `_ascii_hash` from `trust_gate_mcp.server` **after** checking `OAO_RECEIPT_KEY` (OAO reads the
variable at import time), and then requires `openagentontology.receipt._DEFAULT_KEY == os.environ["OAO_RECEIPT_KEY"]`: if OAO was
already imported with a different key, exit 3 (a wrong key that is consistent within a run would otherwise pass every other check). Layout under `OUT`:

```
OUT/.lock
OUT/INSTANCE                      {"instance_name": ..., "url_origin": ...}
OUT/findings/<key>/<seq:06d>.record.json
OUT/findings/<key>/<seq:06d>.receipt.json
OUT/REBIND.<UTC timestamp>        written by --rebind: old and new name/origin
```

### 3.2 `sync`, step by step

1. **Pre-flight.** Exclusive non-blocking `flock` on `OUT/.lock` (held: exit 3). Absolute `--out`, mode 0700. Read or write
   `INSTANCE`; a different name or origin than stored refuses (exit 3) unless `--rebind`. Refuse a non-HTTPS `ARTEX_URL` on a
   non-loopback host unless `--allow-insecure`. `OAO_RECEIPT_KEY` must be set and its file must exist, unless `--init-key`
   (exit 3 otherwise), and OAO must have loaded that same path (section 3.1), so a typo, an unset variable or an earlier import
   cannot silently sign under a different or newly created key.
2. **Login, once.** No retry. 401 is `login_failed`, 429 is `login_blocked`, any other failure is `http_status`; each ends the run
   (exit 1). The token lives in memory only and never appears in output, files, logs or exception text.
3. **Version.** `GET /api/health`; a missing or non-string `version` ends the run with `version_unavailable`. The version is
   recorded in each receipt's manifest, not in the content record (so an ARTEX upgrade does not re-mint everything).
4. **List.** Walk all pages (limit 200), collecting finding keys. After processing, list once more. A key seen first and missing at
   the end, or with receipts on disk and missing now, is `finding_gone` (reported, never silently dropped). Keys that appear
   mid-run are picked up next run. `complete` is true only if both listings walked cleanly.
5. **Per finding**, fetch the detail and build the content record from it using ARTEX's **claimed** hashes (section 4). Then:
   - **Head.** `load_head` takes the highest `seq` that has both a record and a receipt file. It parses both strictly, then runs
     `_verify` (with `require_pq=False`, see step 6) and requires ok, `signed: true` and `issuer_tool == "artex_sync_record"`;
     only then does it read `inputs_hash`, `seq` and `target` from `verified.ontology` and require
     `_ascii_hash(record bytes) == inputs_hash`, `seq` equal to the filename seq, and `target` to match. It does not pin a kid
     (so key rotation causes no mass re-mint; the summary lists the distinct kids seen across heads). It also raises if any
     receipt file exists above the head. Any failure raises `ReceiptInvalid`: the finding is `failed` with `receipt_invalid` and
     nothing new is minted over it (the operator moves the bad files away and re-runs).
   - **Unchanged.** If the head exists and `record_hash(claimed record) == head.inputs_hash`, the finding is `unchanged` and **no
     bodies are downloaded** (one detail request per unchanged finding). Such findings' bodies were hashed when they were
     receipted, not in this run; the summary counts them as `unchanged_bodies_not_rechecked`. `--verify-bodies` re-hashes them too
     and any difference is `evidence_hash_mismatch`. Docs recommend a weekly `--verify-bodies` run.
   - **New or changed.** Stream each body with a hard cap of `min(claimed length, --max-body-bytes) + 1` bytes (more is
     `body_too_large`), hash and count it, compare with the claim (`evidence_hash_mismatch` / `length_mismatch` / `body_missing`).
     Rebuild the record with the hashes this tool computed (equal to the claim, or the finding fails).
6. **Sign.** `seq = head.seq + 1` (1 if no head); a record file at exactly `head.seq + 1` with no receipt is renamed
   `*.orphan.<UTC timestamp>` and replaced, since it may predate a content change (a record file anywhere else without a receipt is
   `receipt_invalid`). `mint_finding` calls `_mint(manifest, "FINDING_RECORDED")`
   (section 5). It then requires: no `error` key, `signed` true, `_verify(receipt, require_pq=False)` ok (integrity only: whether a PQ
   signature is present is reported as `pq_signed`, and a PQ policy is enforced by `verify --require-pq`, never by `sync`, so a host
   without a PQ backend still works), and the same Ed25519 `kid` as every other receipt this run; otherwise `sign_failed` and nothing is written. A crash-retry stamps a new `observed_at`; `signed_at` is the time
   the signature vouches for.
7. **Write**, each file via temp file, fsync, rename: record first, then receipt. A receipt file existing with a record that
   verifies is what "receipted" means; there is no separate state file.
8. **Summary** (stdout JSON, shape below). It asserts `minted + unchanged + failed == unique keys seen in the first listing` or
   reports `count_mismatch` and exits 1. `gone` is counted separately and excluded from that sum; a 404 on a finding's detail request
   is `finding_gone`, any other non-200 is `http_status`. A finding deleted in ARTEX on purpose is acknowledged with
   `--ack-gone KEY` (repeatable), which writes `OUT/findings/<key>/GONE` and stops it from reporting; its receipts stay. `chain_head_sha256` is the hash of the sorted list of `(key, seq, inputs_hash)` of every finding's head; the
   operator can store it elsewhere, which is the only way to notice deletion of the latest receipt of a finding (see section 9).

```json
{"signer_kid":"...","artex_version":"0.6.0","instance_name":"lab","complete":true,"pq_signed":true,
 "minted":3,"unchanged":41,"unchanged_bodies_not_rechecked":41,"failed":1,"gone":0,
 "failures":[{"key":"17","reason":"evidence_hash_mismatch"}],"chain_head_sha256":"sha256:..."}
```

### 3.3 `verify`

`verify RECEIPT RECORD --kid KID` passes only if all hold, reading signed values **only** from `_verify(...)["verified"]` (and its
`ontology`), never from the receipt file's unsigned top level: ok and `signer_pinned` true (`--kid` is required); `issuer_tool == "artex_sync_record"`; `operation`, `policy`, `agent_id`, `decision` equal the
fixed values; the manifest has exactly the keys of section 5 (unknown or duplicate keys fail); `target` matches the pattern and the
record's finding key; the record file's bytes hash (`_ascii_hash`) equals `inputs_hash`; both files parse with the strict hook of
4.1. Output: `{"ok":bool,"signer_pinned":bool,"seq":N,"observed_at":...,"signed_at":...,"artex_version":...,"time_gap_flag":bool,"pq_signed":bool,"reason":...}`
(`time_gap_flag` when `signed_at - observed_at` exceeds one hour). `require_pq` follows the flag, else the environment default.
`verify --chain DIR` additionally checks per finding: sequence numbers contiguous from 1; filename seq equals manifest seq; each
receipt's `previous_inputs_hash` equals the prior receipt's `inputs_hash`; no duplicate seq; and `instance_name` and `url_origin`
unchanged across the chain, otherwise `origin_changed at seq N` and exit 1 unless `--allow-origin-change`.

## 4. The record

### 4.1 Encoding

`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`: pure ASCII, written to the file as
exactly those bytes with no trailing newline. ARTEX input and every file the tool reads are parsed with `parse_constant`
raising, `object_pairs_hook` rejecting duplicate keys, and floats rejected (ints only). **One name for the hash:**
`record_hash(record) = _ascii_hash(record)`, i.e. `"sha256:<hex>"`; the receipt signs it as `inputs_hash`. Golden test vectors pin
the bytes so another language can reproduce them.

### 4.2 Keys and identity

`finding_key` is ARTEX's standalone `finding_id`. Missing, or `id != finding_id`, is `bad_id`. It must satisfy
`re.fullmatch(r"[0-9A-Za-z_-]{1,64}", key, re.ASCII)` and is the only form used in the target, directory name and lookups.
`instance_name` is chosen by the operator (same pattern), stored in `INSTANCE`. It is a label for this deployment, not proof of
identity; a change needs `--rebind` and shows in the chain verifier.

### 4.3 Fields (schema `artex-sync/record/v1`, the CONTENT record)

Required unless marked `?`. A `?` field is always present in the record: `null` when ARTEX omitted it, never the hash of an empty
string.

```
schema "artex-sync/record/v1"
finding.key, finding.name?, finding.vulnclass, finding.severity, finding.status, finding.verification_status,
finding.poe_level (int), finding.task_id?, finding.evidence_version (int), finding.created_ts (str as sent)
finding.summary_sha256, finding.evidence_sha256, finding.report_sha256?, finding.verification_note_sha256?,
finding.counterevidence_sha256?, finding.confidence_rationale_sha256?      (sha256 hex of the UTF-8 text)
finding.assets: [{id, type, label_sha256}] sorted by id     ([] if none)
finding.unbound_keys: sorted list of top-level keys ARTEX returned that this schema does not bind
traffic: [{binding_id, role, position, note_sha256?, snapshot_id, method, status, captured_at (int), url_sha256,
           req_sha256, req_len, resp_sha256, resp_len}] sorted by position then binding_id      ([] if none)
```

Types are strict (str is str, int is int and not bool, hashes match `^[0-9a-f]{64}$`, lengths are non-negative ints). The record has
no fetch time, no ARTEX version, no origin and no link to earlier records, so identical content always yields identical bytes.

## 5. The receipt

Signed through `_mint` (not `tool_mint_action_receipt`, so no MCP client can produce an equivalent receipt), manifest exactly:

```
operation "artex finding recorded"      issuer_tool "artex_sync_record"      agent_id "trust-gate-artex"
policy "artex-sync record v1"           target "artex:<instance_name>/finding/<finding_key>"      (ids only)
inputs_hash record_hash(record)         seq int (1, then +1 per change)      previous_inputs_hash str | null (null iff seq 1)
observed_at RFC 3339 UTC, start of this finding's fetch in the run that minted it
artex_version str from /api/health      artex_origin scheme://host:port of ARTEX_URL
```

`decision` is `FINDING_RECORDED`. A finding that changes A to B to A produces three receipts, since "unchanged" compares only with
the head.

## 6. Failure, limits, fail closed

Reason codes (fixed list; nothing else is emitted): `login_failed`, `login_blocked`, `version_unavailable`, `http_status`,
`redirect`, `bad_json`, `json_too_large`, `missing_field`, `bad_type`, `bad_id`, `bad_text`, `evidence_hash_mismatch`,
`length_mismatch`, `body_missing`, `body_too_large`, `too_many_bindings`, `receipt_invalid`, `sign_failed`, `write_failed`,
`finding_gone`, `count_mismatch`, `deadline_exceeded`.

- A failed finding gets no receipt and nothing partial is written. An absent value is never replaced by a default: it is `null`
  where 4.3 allows, otherwise `missing_field`.
- `httpx.Client` as in `api_ops.py`: `follow_redirects=False` (any 3xx is `redirect`), `trust_env=False`, timeouts, TLS verification
  on. JSON responses capped at 8 MiB. At most 500 bindings per finding. Run deadline 6 hours.
- Paths used on ARTEX: login, health, findings list, finding detail, traffic body. Recommended: a reverse proxy allowing exactly
  those (the account is full admin and v0.6.0 has no scoped tokens).
- ARTEX output is data: hashed or copied into typed JSON fields, never executed, never a path other than the validated key, never
  logged beyond ids and reason codes. Output files 0600, directory 0700.

## 7. What a verifier can and cannot conclude

Can: the holder of the pinned key signed this record for this deployment label at `signed_at`; the record file is unchanged; each
body hash in it is one the tool computed from bytes ARTEX served at the time that finding was last receipted; a finding's receipts
form a contiguous chain. Cannot: that the finding is real, that the bodies came from the target (a hostile or compromised ARTEX
controls everything it serves), that the test was authorised, that no finding was withheld, or that an unchanged finding's stored
bodies are still the same today unless `--verify-bodies` ran. Fields in `unbound_keys` are not covered.

## 8. Files, tests, packaging

Add `src/trust_gate_mcp/artex_sync.py` and `tests/test_artex_sync.py`. Change `pyproject.toml` (`trust-gate-artex` script; no new
dependency), `docs/artex.md` ("Receipt every finding": install on the host, point `OAO_RECEIPT_KEY` at the server's key file or
volume path, `OAO_REQUIRE_PQ` note, cron example with `/srv/example/...` placeholder paths, reverse-proxy allowlist, weekly
`--verify-bodies`, local-disk `OUT`), `CHANGELOG.md` (Unreleased), `tests/test_release_consistency.py` (`SHIPPED_TEXT` gains the
module and doc). Unchanged: `server.py` tools, Dockerfile, version numbers. Python 3.10 compatible (`from __future__ import
annotations`). CI is the existing `pytest tests -q` on 3.10 and 3.12; no extra Actions minutes.

Tests use an `httpx.MockTransport` fake of ARTEX and a temporary `OAO_RECEIPT_KEY`: happy path; unchanged rerun mints nothing,
downloads no bodies, despite a different fetch time; change mints seq 2 with the right `previous_inputs_hash`; A to B to A mints
three; ARTEX version bump that adds no new top-level key mints nothing (a new key changes `unbound_keys` and re-mints once, by design); zero bindings and omitted optional keys; hash and length mismatch, oversized body,
oversized JSON, redirect on body and on list; 401 with no retry, 429; missing field, wrong type, bad id (newline, unicode digits,
`..`, 65 chars, `id != finding_id`); lone surrogate and NUL; duplicate JSON key; `finding_gone`; `total` moving mid-run; arithmetic
mismatch; two concurrent runs (lock); crash after record before receipt, with unchanged and with changed content (orphan rule);
latest receipt tampered, truncated, `signed: false`, or unsigned-key (`receipt_invalid`, no skip, no re-mint); `seq` vs filename
mismatch; `OAO_RECEIPT_KEY` unset or missing file, with and without `--init-key`; OAO already loaded with a different `_DEFAULT_KEY` (exit 3); host with no PQ backend (sync works, `pq_signed` false); a receipt file above the head, a record file with no receipt above head+1, a repeated crash (unique orphan suffix); `--ack-gone`; mixed kid in one run; `--rebind` flow and chain
verification across it; verify rejects an edited record, no `--kid`, a receipt from `mint_action_receipt` with the same strings, a
wrong `issuer_tool`, extra or duplicate manifest keys, a chain gap, a chain origin change; `--require-pq` on and off; token never
in stdout, stderr or files; file modes; golden canonical bytes; non-POSIX exit 3; and the existing release-consistency test.

## 9. Operations and rollback

Additive: rollback is to stop the cron and `pip install` the earlier version; issued receipts stay valid (each carries its kid).
Key rotation: new receipts use the new key; heads signed by an older key still verify with their own embedded key, so rotation
causes no mass re-mint. Losing `OUT` loses the skip and chain state: the next run re-mints at seq 1 for every finding and the
chain no longer links to old receipts, so back up `OUT` together with the signing key. **Known limit:** deleting a finding's latest
receipt (and record) is not detectable from `OUT` alone, because the earlier receipt then looks like the head; store
`chain_head_sha256` from the summary somewhere else to notice.

## 10. Review log

### Round 3 (one reviewer, three lenses): NOT CLEAN, 0 Blockers, 3 Majors, 8 Nits; last round, all FIX in v3.1

r3-ready-1 (`require_pq` in sync's own checks): integrity-only `_verify`, PQ policy only on `verify`. r3-ready-2 (key loaded by OAO
at import): `_DEFAULT_KEY` must equal the env path. r3-critic-1 (stray files above the head): `load_head` raises; unique orphan
suffix; only head+1 is an orphan. r3-critic-2 (verify before trusting manifest values; no kid pin in `load_head`): stated.
r3-critic-3 (`gone` and the arithmetic, 404): stated. r3-critic-4 (version bump test wording): reworded. r3-critic-5 (permanent
`finding_gone`): `--ack-gone`. r3-ready-3 (`--kid` required, exit codes of `verify`): stated. r3-ready-4 (Windows `verify`): lazy
`fcntl`. r3-ready-5 (types, `bodies` key): defined. r3-comp-1 (glossary): added. No further review round is run (round-3 hard
stop); open items for the founder: none beyond the CONTESTs above.

### Round 1 (comprehension, critic, zoom-out + readiness)

Blockers: critic-1-1 (hash and surrogates), critic-1-2 (lookalike receipts), critic-1-3 / ready-1-6 / ready-1-7 / comp-1-1 / comp-1-3
(absent vs null, version), ready-1-1 (fetch time in the digest): all FIX (4.1, 5, 4.3, 3.2).
Majors FIX: listing completeness and arithmetic; omitted fields (`unbound_keys`, more hashed fields, narrowed claim); canonical
JSON; crash and concurrency; chain derived from files with a verifier; operator-chosen instance name; verifier limits (section 7);
id regex; body caps and rerun cost; A-B-A; hash prefix and bytes; verify pinning and fields; login lockout; packaging, tests,
rollback; which key. CONTEST (settled): zoom-1-1 (no named customer: Spectre asked for this as the customer piece), zoom-1-3 (state
file and random instance id dropped; chaining and verify kept, because chaining makes a removed change visible and an unverifiable
receipt is not a product).

### Round 2 (one reviewer, three lenses): NOT CLEAN, 0 Blockers, 5 critic Majors, 3 readiness Majors, all FIX in v3

r2-critic-1 (skip trusts an unchecked receipt): `load_head` verifies hash, seq, target and signature; `receipt_invalid`, never
re-mint over it. r2-critic-2 (skip-by-claimed-hash): summary `unchanged_bodies_not_rechecked`, weekly `--verify-bodies`, section 7
wording. r2-critic-3 (`artex.version` mass re-mint): version and origin moved to the signed manifest, out of the content record.
r2-critic-4 (seq derivation): defined head, padded filenames, manifest seq must equal filename, orphan rule, `chain_head_sha256`,
known limit in section 9. r2-critic-5 (wrong or unsigned key): `OAO_RECEIPT_KEY` required and read before importing OAO, `signed`
and `_verify` checked after each mint, one kid per run. r2-critic-6 (`--rebind`, origin continuity): in the synopsis, chain checks
origin. r2-critic-7 (verify parsing): strict parsing, signed values read only from `_verify`, exact key set. r2-critic-8 covered by
-4. r2-critic-9 (flock): local disk, POSIX only. r2-critic-10 (`observed_at` on retry): restamped, `signed_at` is authoritative.
r2-ready-1 and -2 (surface and field names): sections 3.1, 3.2 sample summary, 3.3 sample verify output; naming unified on
`record_hash` / `inputs_hash`. r2-ready-3 (crash rule): step 6. r2-ready-4..8: imports named, exit 3 without OAO, tests added,
other HTTP statuses are `http_status`.
