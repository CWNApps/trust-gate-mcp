"""artex_sync.py -- give every ARTEX finding a signed TrustGate receipt.

ARTEX (https://github.com/BaaRai/ARTEX, AGPL-3.0, a separate project) is a self-hosted autonomous
penetration-testing platform. This tool runs next to a customer's ARTEX, reads its findings and the
hashes of the HTTP evidence behind them over ARTEX's REST API, and signs one receipt per finding (and
per change to a finding) with this package's signing key. Receipts carry hashes and ids, never target
data. Design and review record: docs/designs/artex_sync.md.

    trust-gate-artex sync   --out DIR --instance-name NAME [...]
    trust-gate-artex verify RECEIPT RECORD --kid KID
    trust-gate-artex verify --chain DIR --kid KID

A receipt says: the holder of the signing key saw this ARTEX API return this finding, with these
evidence-body hashes, at about this time. It does not say the finding is true or that anyone authorised
the test.
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

SCHEMA = "artex-sync/record/v1"
OPERATION = "artex finding recorded"
ISSUER_TOOL = "artex_sync_record"
AGENT_ID = "trust-gate-artex"
POLICY = "artex-sync record v1"
DECISION = "FINDING_RECORDED"
MANIFEST_KEYS = frozenset({
    "operation", "issuer_tool", "agent_id", "policy", "target", "inputs_hash", "seq",
    "previous_inputs_hash", "observed_at", "artex_version", "artex_origin",
})

REASONS = frozenset({
    "login_failed", "login_blocked", "version_unavailable", "http_status", "redirect", "bad_json",
    "json_too_large", "missing_field", "bad_type", "bad_id", "bad_text", "evidence_hash_mismatch",
    "length_mismatch", "body_missing", "body_too_large", "too_many_bindings", "receipt_invalid",
    "sign_failed", "write_failed", "finding_gone", "count_mismatch", "deadline_exceeded", "evidence_changed",
})

_KEY_RE = re.compile(r"[0-9A-Za-z_-]{1,64}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_TARGET_RE = re.compile(r"artex:([0-9A-Za-z_-]{1,64})/finding/([0-9A-Za-z_-]{1,64})")
_FILE_RE = re.compile(r"(\d{6})\.(record|receipt)\.json")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_BINDINGS = 500
RUN_DEADLINE_SECONDS = 6 * 3600
DEFAULT_MAX_BODY = 256 * 1024 * 1024
TIME_GAP_SECONDS = 3600

# Top-level keys of ARTEX's finding detail that the record binds. Anything else ARTEX returns is listed
# (by name only) in finding.unbound_keys.
_BOUND_KEYS = frozenset({
    "id", "finding_id", "name", "vulnclass", "severity", "status", "verification_status", "poe_level",
    "task_id", "evidence_version", "ts", "summary", "evidence", "report", "verification_note",
    "counterevidence", "confidence_rationale", "assets", "traffic_bindings",
})


# --------------------------------------------------------------------------- errors


class Fail(Exception):
    """One finding (or the run) cannot be receipted. `reason` is always one of REASONS."""

    def __init__(self, reason: str, status: Optional[int] = None):
        assert reason in REASONS, reason
        super().__init__(reason)
        self.reason = reason
        self.status = status


class ReceiptInvalid(Exception):
    """A receipt or record already on disk does not check out; nothing is minted over it."""


class Preflight(Exception):
    """A pre-flight refusal (exit 3)."""


# --------------------------------------------------------------------------- strict JSON


def _no_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _no_float(text: str) -> Any:
    raise ValueError("floats are not allowed")


def _no_dupes(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def strict_loads(data: "bytes | str") -> Any:
    """Parse JSON the way every file and ARTEX answer in this tool is parsed: no NaN or Infinity, no
    floats, no duplicate keys. Raises ValueError (including json.JSONDecodeError and bad UTF-8)."""
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    return json.loads(text, parse_constant=_no_constant, parse_float=_no_float, object_pairs_hook=_no_dupes)


def canonical(obj: Any) -> str:
    """The canonical record string: sorted keys, no whitespace, pure ASCII, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


# --------------------------------------------------------------------------- server.py bridge


def _srv() -> Any:
    from trust_gate_mcp import server as srv  # imported late: OAO reads OAO_RECEIPT_KEY at import time
    if getattr(srv, "_oao_receipt", None) is None:
        raise Preflight("openagentontology is not installed; cannot sign or verify")
    return srv


def record_hash(record: str) -> str:
    """"sha256:<hex>" of the record string, the same value the receipt signs as inputs_hash."""
    return _srv()._ascii_hash(record)


# --------------------------------------------------------------------------- record


def _typed(d: Dict[str, Any], key: str, typ: type, *, optional: bool = False) -> Any:
    if key not in d or d[key] is None:
        if optional:
            return None
        raise Fail("missing_field")
    v = d[key]
    if typ is int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise Fail("bad_type")
    elif not isinstance(v, typ) or isinstance(v, bool):
        raise Fail("bad_type")
    return v


def _text_sha(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    try:
        return hashlib.sha256(v.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:  # a lone surrogate cannot be written as UTF-8
        raise Fail("bad_text")


def _claimed_hash(snap: Dict[str, Any], side: str) -> Tuple[str, int]:
    length = _typed(snap, f"{'req' if side == 'request' else 'resp'}_len", int)
    h = snap.get(f"{'req' if side == 'request' else 'resp'}_hash")
    if length < 0:
        raise Fail("bad_type")
    if not isinstance(h, str):
        raise Fail("missing_field" if h is None else "bad_type")
    h = h.lower()
    if length == 0 and h == "":
        return _EMPTY_SHA256, 0
    if not _HEX64_RE.fullmatch(h):
        raise Fail("bad_type")
    return h, length


def finding_key(d: Dict[str, Any]) -> str:
    """The finding's key: its standalone finding_id; id must agree."""
    fid = d.get("finding_id")
    if not isinstance(fid, str) or not _KEY_RE.fullmatch(fid):
        raise Fail("bad_id")
    if "id" in d and d["id"] != fid:
        raise Fail("bad_id")
    return fid


def _bindings(detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = detail.get("traffic_bindings")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise Fail("bad_type")
    if len(raw) > MAX_BINDINGS:
        raise Fail("too_many_bindings")
    out = []
    for b in raw:
        if not isinstance(b, dict):
            raise Fail("bad_type")
        bid = b.get("id")
        if not isinstance(bid, str) or not _KEY_RE.fullmatch(bid):
            raise Fail("bad_id")
        if not isinstance(b.get("snapshot"), dict):
            raise Fail("missing_field")
        out.append(b)
    return out


def claimed_bodies(detail: Dict[str, Any]) -> Dict[Tuple[str, str], Tuple[str, int]]:
    """ARTEX's own claim of (sha256, length) for every evidence body of the finding."""
    out: Dict[Tuple[str, str], Tuple[str, int]] = {}
    for b in _bindings(detail):
        for side in ("request", "response"):
            out[(b["id"], side)] = _claimed_hash(b["snapshot"], side)
    return out


def build_record(detail: Dict[str, Any],
                 bodies: Optional[Dict[Tuple[str, str], Tuple[str, int]]] = None) -> str:
    """The canonical content record (section 4 of the design) for one finding detail.

    `bodies` maps (binding_id, "request"|"response") to (sha256 hex, length) as this tool computed them;
    when None, ARTEX's claimed values are used (to decide whether a finding changed without downloading).
    """
    key = finding_key(detail)
    if bodies is None:
        bodies = claimed_bodies(detail)
    assets = []
    raw_assets = detail.get("assets")
    if raw_assets is not None:
        if not isinstance(raw_assets, list):
            raise Fail("bad_type")
        for a in raw_assets:
            if not isinstance(a, dict):
                raise Fail("bad_type")
            assets.append({"id": _typed(a, "id", str), "type": _typed(a, "type", str),
                           "label_sha256": _text_sha(_typed(a, "label", str))})
        assets.sort(key=lambda x: x["id"])
    traffic = []
    for b in _bindings(detail):
        snap = b["snapshot"]
        bid = b["id"]
        req = bodies.get((bid, "request"))
        resp = bodies.get((bid, "response"))
        if req is None or resp is None:
            raise Fail("missing_field")
        traffic.append({
            "binding_id": bid,
            "role": _typed(b, "role", str),
            "position": _typed(b, "position", int),
            "note_sha256": _text_sha(_typed(b, "note", str, optional=True)),
            "snapshot_id": _typed(snap, "id", str),
            "method": _typed(snap, "method", str),
            "status": _typed(snap, "status", int),
            "captured_at": _typed(snap, "captured_at", int),
            "url_sha256": _text_sha(_typed(snap, "url", str)),
            "req_sha256": req[0], "req_len": req[1],
            "resp_sha256": resp[0], "resp_len": resp[1],
        })
    traffic.sort(key=lambda x: (x["position"], x["binding_id"]))
    record = {
        "schema": SCHEMA,
        "finding": {
            "key": key,
            "name": _typed(detail, "name", str, optional=True),
            "vulnclass": _typed(detail, "vulnclass", str),
            "severity": _typed(detail, "severity", str),
            "status": _typed(detail, "status", str),
            "verification_status": _typed(detail, "verification_status", str),
            "poe_level": _typed(detail, "poe_level", int),
            "task_id": _typed(detail, "task_id", str, optional=True),
            "evidence_version": _typed(detail, "evidence_version", int),
            "created_ts": _typed(detail, "ts", str),
            "summary_sha256": _text_sha(_typed(detail, "summary", str)),
            "evidence_sha256": _text_sha(_typed(detail, "evidence", str)),
            "report_sha256": _text_sha(_typed(detail, "report", str, optional=True)),
            "verification_note_sha256": _text_sha(_typed(detail, "verification_note", str, optional=True)),
            "counterevidence_sha256": _text_sha(_typed(detail, "counterevidence", str, optional=True)),
            "confidence_rationale_sha256": _text_sha(_typed(detail, "confidence_rationale", str, optional=True)),
            "assets": assets,
            "unbound_keys": sorted(str(k) for k in detail if k not in _BOUND_KEYS),
        },
        "traffic": traffic,
    }
    return canonical(record)


# --------------------------------------------------------------------------- ARTEX client


def _client_factory(timeout: float) -> Any:
    """The HTTP client. Tests replace this with one on a mocked transport."""
    import httpx
    # trust_env=False: never take proxy or netrc settings from the environment; follow_redirects=False:
    # a redirect is a failure here, never something to follow with credentials attached.
    return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)


class ArtexApi:
    def __init__(self, client: Any, base_url: str):
        self.client = client
        self.base = base_url.rstrip("/")
        self.token: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @contextlib.contextmanager
    def _stream(self, method: str, path: str, **kw: Any) -> Iterator[Any]:
        import httpx
        try:
            with self.client.stream(method, self.base + path, headers=self._headers(), **kw) as resp:
                if 300 <= resp.status_code < 400:
                    raise Fail("redirect", resp.status_code)
                yield resp
        except Fail:
            raise
        except httpx.HTTPError:
            raise Fail("http_status")

    def _json(self, method: str, path: str, **kw: Any) -> Any:
        with self._stream(method, path, **kw) as resp:
            if resp.status_code != 200:
                raise Fail("http_status", resp.status_code)
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf += chunk
                if len(buf) > MAX_JSON_BYTES:
                    raise Fail("json_too_large")
        try:
            return strict_loads(bytes(buf))
        except ValueError:
            raise Fail("bad_json")

    def login(self, username: str, password: str) -> None:
        try:
            with self._stream("POST", "/api/auth/login", json={"username": username, "password": password}) as resp:
                if resp.status_code == 401:
                    raise Fail("login_failed", 401)
                if resp.status_code == 429:
                    raise Fail("login_blocked", 429)
                if resp.status_code != 200:
                    raise Fail("http_status", resp.status_code)
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_JSON_BYTES:
                        raise Fail("json_too_large")
            body = strict_loads(bytes(buf))
        except ValueError:
            raise Fail("bad_json")
        tok = body.get("token") if isinstance(body, dict) else None
        if not isinstance(tok, str) or not tok:
            raise Fail("bad_json")
        self.token = tok

    def version(self) -> str:
        body = self._json("GET", "/api/health")
        v = body.get("version") if isinstance(body, dict) else None
        if not isinstance(v, str) or not v:
            raise Fail("version_unavailable")
        return v

    def list_pages(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        page = 1
        while page <= 10000:
            body = self._json("GET", "/api/exploration/findings", params={"page": page, "limit": 200})
            if not isinstance(body, dict) or not isinstance(body.get("items"), list) \
                    or isinstance(body.get("total"), bool) or not isinstance(body.get("total"), int):
                raise Fail("bad_json")
            if not body["items"]:
                break
            items.extend(body["items"])
            if len(items) >= body["total"]:
                break
            page += 1
        return items

    def detail(self, key: str) -> Dict[str, Any]:
        body = self._json("GET", f"/api/exploration/findings/{key}")
        if not isinstance(body, dict):
            raise Fail("bad_json")
        return body

    def detail_with_traffic(self, key: str) -> Dict[str, Any]:
        """The finding detail plus its evidence bindings. ARTEX v0.6.0 serves the bindings only from
        GET .../findings/{id}/traffic (the detail omits them), as {"finding_id", "version", "bindings": [...]}.
        The two answers must describe the same evidence version and the same number of bindings."""
        detail = self.detail(key)
        body = self._json("GET", f"/api/exploration/findings/{key}/traffic")
        if not isinstance(body, dict) or not isinstance(body.get("bindings"), list):
            raise Fail("bad_json")
        if body.get("finding_id") != key:
            raise Fail("bad_id")
        ver, count = detail.get("evidence_version"), detail.get("traffic_count")
        if isinstance(body.get("version"), bool) or body.get("version") != ver:
            raise Fail("evidence_changed")
        if count is not None and (isinstance(count, bool) or count != len(body["bindings"])):
            raise Fail("evidence_changed")
        merged = dict(detail)
        merged["traffic_bindings"] = body["bindings"]
        return merged

    def hash_body(self, key: str, binding_id: str, side: str, claimed_len: int, max_body: int) -> Tuple[str, int]:
        if claimed_len > max_body:
            raise Fail("body_too_large")
        h = hashlib.sha256()
        n = 0
        path = f"/api/exploration/findings/{key}/traffic/{binding_id}/body"
        with self._stream("GET", path, params={"side": side, "download": "1"}) as resp:
            if resp.status_code == 404:
                raise Fail("body_missing", 404)
            if resp.status_code != 200:
                raise Fail("http_status", resp.status_code)
            for chunk in resp.iter_bytes():
                n += len(chunk)
                if n > claimed_len:
                    raise Fail("length_mismatch")
                h.update(chunk)
        return h.hexdigest(), n


# --------------------------------------------------------------------------- files


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError):
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def _iso(t: _dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(s: Any) -> Optional[_dt.datetime]:
    if not isinstance(s, str):
        return None
    try:
        t = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)


def _target(instance: str, key: str) -> str:
    return f"artex:{instance}/finding/{key}"


def _seq_files(d: Path) -> Tuple[Dict[int, Path], Dict[int, Path]]:
    records: Dict[int, Path] = {}
    receipts: Dict[int, Path] = {}
    if d.is_dir():
        for p in d.iterdir():
            m = _FILE_RE.fullmatch(p.name)
            if m:
                (records if m.group(2) == "record" else receipts)[int(m.group(1))] = p
    return records, receipts


# --------------------------------------------------------------------------- verification


@dataclasses.dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str = ""
    signer_pinned: bool = False
    seq: Optional[int] = None
    inputs_hash: Optional[str] = None
    previous_inputs_hash: Optional[str] = None
    instance_name: Optional[str] = None
    key: Optional[str] = None
    observed_at: Optional[str] = None
    signed_at: Optional[str] = None
    artex_version: Optional[str] = None
    artex_origin: Optional[str] = None
    time_gap_flag: bool = False
    pq_signed: bool = False
    kid: str = ""

    def as_json(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        for k in ("inputs_hash", "previous_inputs_hash", "instance_name", "key", "artex_origin"):
            d.pop(k)
        return d


def _bad(reason: str) -> VerifyResult:
    return VerifyResult(ok=False, reason=reason)


def verify_pair(receipt_bytes: bytes, record_bytes: bytes, *, kid: Optional[str],
                require_pq: Optional[bool], expect_seq: Optional[int] = None,
                expect_key: Optional[str] = None, expect_instance: Optional[str] = None) -> VerifyResult:
    """Check one receipt file against its record file. Signed values are read only from what
    `_verify` returns (never from the unsigned top level of the file)."""
    srv = _srv()
    try:
        receipt = strict_loads(receipt_bytes)
        record = strict_loads(record_bytes)
        record_text = record_bytes.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return _bad("receipt or record is not strict JSON")
    if not isinstance(receipt, dict) or not isinstance(record, dict):
        return _bad("receipt or record is not a JSON object")
    if canonical(record) != record_text:
        return _bad("record is not in canonical form")
    out = srv._verify(receipt, require_pq=require_pq, expected_kid=kid)
    if not out.get("ok"):
        return _bad(f"signature check failed: {out.get('reason', 'unknown')}"[:300])
    if not out.get("signed"):
        return _bad("receipt is unsigned")
    pinned = bool(out.get("signer_pinned"))
    if kid is not None and not pinned:
        return _bad("signer is not the pinned kid")
    verified = out.get("verified") or {}
    onto = verified.get("ontology")
    if verified.get("issuer_tool") != ISSUER_TOOL or not isinstance(onto, dict):
        return _bad("receipt was not issued by artex-sync")
    if set(onto) != MANIFEST_KEYS:
        return _bad("manifest keys are not exactly the artex-sync set")
    fixed = (("operation", OPERATION), ("policy", POLICY), ("agent_id", AGENT_ID))
    if any(onto.get(k) != v for k, v in fixed) or verified.get("decision") != DECISION:
        return _bad("operation, policy, agent or decision is not the artex-sync value")
    m = _TARGET_RE.fullmatch(onto["target"]) if isinstance(onto.get("target"), str) else None
    if not m:
        return _bad("target is not an artex-sync target")
    instance, key = m.group(1), m.group(2)
    if (expect_key is not None and key != expect_key) or (expect_instance is not None and instance != expect_instance):
        return _bad("target does not match the expected instance and finding")
    finding = record.get("finding")
    if record.get("schema") != SCHEMA or not isinstance(finding, dict) or finding.get("key") != key:
        return _bad("record schema or finding key does not match the receipt target")
    ih = onto.get("inputs_hash")
    if not isinstance(ih, str) or srv._ascii_hash(record_text) != ih:
        return _bad("record hash does not match the signed inputs_hash")
    seq, prev = onto.get("seq"), onto.get("previous_inputs_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        return _bad("seq is not a positive integer")
    if (seq == 1) != (prev is None) or (prev is not None and not isinstance(prev, str)):
        return _bad("previous_inputs_hash must be null exactly when seq is 1")
    if expect_seq is not None and seq != expect_seq:
        return _bad("seq does not match the file name")
    for k in ("observed_at", "artex_version", "artex_origin"):
        if not isinstance(onto.get(k), str) or not onto[k]:
            return _bad(f"{k} is missing")
    obs, sig = _parse_time(onto["observed_at"]), _parse_time(verified.get("signed_at"))
    gap = bool(obs and sig and (sig - obs).total_seconds() > TIME_GAP_SECONDS)
    legs = out.get("legs") if isinstance(out.get("legs"), dict) else {}
    return VerifyResult(
        ok=True, signer_pinned=pinned, seq=seq, inputs_hash=ih, previous_inputs_hash=prev,
        instance_name=instance, key=key, observed_at=onto["observed_at"], signed_at=verified.get("signed_at"),
        artex_version=onto["artex_version"], artex_origin=onto["artex_origin"], time_gap_flag=gap,
        pq_signed=any(legs.get(n) == "ok" for n in ("ml_dsa", "slh_dsa")), kid=str(out.get("kid") or ""))


def verify_chain(out: Path, kid: str, *, allow_origin_change: bool, require_pq: Optional[bool]) -> Dict[str, Any]:
    """Check every finding under OUT/findings: contiguous seq, filename = manifest seq, previous_inputs_hash
    links, one instance name and ARTEX origin throughout (unless allowed)."""
    problems: List[Dict[str, str]] = []
    checked = 0
    fdir = out / "findings"
    for d in sorted(p for p in fdir.iterdir() if p.is_dir()) if fdir.is_dir() else []:
        records, receipts = _seq_files(d)
        seqs = sorted(set(records) | set(receipts))
        if not seqs:
            continue
        if seqs != list(range(1, len(seqs) + 1)) or set(records) != set(receipts):
            problems.append({"key": d.name, "problem": "sequence has a gap or a record/receipt is missing"})
            continue
        prev: Optional[VerifyResult] = None
        for s in seqs:
            try:
                r = verify_pair(receipts[s].read_bytes(), records[s].read_bytes(), kid=kid, require_pq=require_pq,
                                expect_seq=s, expect_key=d.name)
            except OSError:
                problems.append({"key": d.name, "problem": f"seq {s}: unreadable"})
                break
            checked += 1
            if not r.ok:
                problems.append({"key": d.name, "problem": f"seq {s}: {r.reason}"})
                break
            if prev is not None:
                if r.previous_inputs_hash != prev.inputs_hash:
                    problems.append({"key": d.name, "problem": f"seq {s}: previous_inputs_hash does not match seq {s - 1}"})
                    break
                if not allow_origin_change and (r.instance_name, r.artex_origin) != (prev.instance_name, prev.artex_origin):
                    problems.append({"key": d.name, "problem": f"origin_changed at seq {s}"})
                    break
            prev = r
    return {"ok": not problems, "receipts_checked": checked, "problems": problems}


# --------------------------------------------------------------------------- head and mint


@dataclasses.dataclass(frozen=True)
class Head:
    seq: int
    inputs_hash: str
    kid: str
    orphan_seq: Optional[int] = None


def load_head(findings_dir: Path, key: str, instance_name: str) -> Optional[Head]:
    """The finding's latest verified receipt, or None if it has none. Raises ReceiptInvalid on anything that
    does not check out. Does not pin a kid (key rotation must not re-mint everything)."""
    d = findings_dir / key
    records, receipts = _seq_files(d)
    both = sorted(set(records) & set(receipts))
    if any(s not in records for s in receipts):
        raise ReceiptInvalid("receipt without its record")
    head_seq = both[-1] if both else 0
    if both != list(range(1, head_seq + 1)):
        raise ReceiptInvalid("gap in the sequence")
    if any(s > head_seq for s in receipts):
        raise ReceiptInvalid("receipt above the head")
    stray = [s for s in records if s > head_seq]
    if any(s != head_seq + 1 for s in stray):
        raise ReceiptInvalid("record file above head+1")
    orphan = head_seq + 1 if stray else None
    if head_seq == 0:
        return None if orphan is None else Head(0, "", "", orphan)
    try:
        r = verify_pair(receipts[head_seq].read_bytes(), records[head_seq].read_bytes(), kid=None, require_pq=False,
                        expect_seq=head_seq, expect_key=key, expect_instance=instance_name)
    except OSError:
        raise ReceiptInvalid("unreadable head")
    if not r.ok:
        raise ReceiptInvalid(r.reason)
    return Head(head_seq, r.inputs_hash or "", r.kid, orphan)


@dataclasses.dataclass
class RunMeta:
    instance_name: str
    artex_version: str
    artex_origin: str
    kid: Optional[str] = None
    pq_all: bool = True
    minted_any: bool = False


def mint_finding(record: str, key: str, seq: int, previous: Optional[str], meta: RunMeta,
                 observed_at: str) -> Dict[str, Any]:
    srv = _srv()
    manifest = {
        "operation": OPERATION, "issuer_tool": ISSUER_TOOL, "agent_id": AGENT_ID, "policy": POLICY,
        "target": _target(meta.instance_name, key), "inputs_hash": srv._ascii_hash(record),
        "seq": seq, "previous_inputs_hash": previous, "observed_at": observed_at,
        "artex_version": meta.artex_version, "artex_origin": meta.artex_origin,
    }
    receipt = srv._mint(manifest, DECISION)
    if not isinstance(receipt, dict) or "error" in receipt or receipt.get("signed") is not True:
        raise Fail("sign_failed")
    chk = srv._verify(receipt, require_pq=False)
    if not chk.get("ok") or not chk.get("signed"):
        raise Fail("sign_failed")
    kid = str(chk.get("kid") or "")
    if not kid or (meta.kid is not None and kid != meta.kid):
        raise Fail("sign_failed")
    meta.kid = kid
    legs = chk.get("legs") if isinstance(chk.get("legs"), dict) else {}
    meta.pq_all = meta.pq_all and any(legs.get(n) == "ok" for n in ("ml_dsa", "slh_dsa"))
    meta.minted_any = True
    return receipt


# --------------------------------------------------------------------------- sync


@dataclasses.dataclass(frozen=True)
class Options:
    max_body_bytes: int = DEFAULT_MAX_BODY
    verify_bodies: bool = False
    rebind: bool = False
    ack_gone: Tuple[str, ...] = ()
    deadline_seconds: float = RUN_DEADLINE_SECONDS


@dataclasses.dataclass
class Summary:
    signer_kid: str = ""
    artex_version: str = ""
    instance_name: str = ""
    complete: bool = False
    pq_signed: Optional[bool] = None
    minted: int = 0
    unchanged: int = 0
    unchanged_bodies_not_rechecked: int = 0
    failed: int = 0
    gone: int = 0
    failures: List[Dict[str, str]] = dataclasses.field(default_factory=list)
    kids_seen: List[str] = dataclasses.field(default_factory=list)
    chain_head_sha256: str = ""
    exit_code: int = 0

    def as_json(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d.pop("exit_code")
        return d


def _chain_head_hash(findings_dir: Path) -> str:
    srv = _srv()
    rows: List[List[Any]] = []
    if findings_dir.is_dir():
        for d in sorted(p for p in findings_dir.iterdir() if p.is_dir()):
            records, receipts = _seq_files(d)
            both = sorted(set(records) & set(receipts))
            if not both:
                continue
            try:
                r = strict_loads(receipts[both[-1]].read_bytes())
                ih = r["evidence"]["ontology"]["inputs_hash"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            rows.append([d.name, both[-1], ih])
    return srv._ascii_hash(canonical(rows))


def _disk_keys(findings_dir: Path) -> List[str]:
    keys = []
    if findings_dir.is_dir():
        for d in findings_dir.iterdir():
            if d.is_dir() and not (d / "GONE").exists() and _seq_files(d)[1]:
                keys.append(d.name)
    return sorted(keys)


def _fail(summary: Summary, key: str, reason: str) -> None:
    summary.failed += 1
    summary.failures.append({"key": key, "reason": reason})


def sync(api: ArtexApi, out: Path, instance_name: str, artex_origin: str, opts: Options) -> Summary:
    summary = Summary(instance_name=instance_name)
    findings_dir = out / "findings"
    findings_dir.mkdir(mode=0o700, exist_ok=True)
    for key in opts.ack_gone:
        (findings_dir / key).mkdir(mode=0o700, exist_ok=True)
        _atomic_write(findings_dir / key / "GONE", b"acknowledged\n")

    started = time.monotonic()
    try:
        summary.artex_version = api.version()
        items = api.list_pages()
    except Fail as e:
        _fail(summary, "*", e.reason)
        summary.exit_code = 1
        return summary

    meta = RunMeta(instance_name, summary.artex_version, artex_origin)
    keys: List[str] = []
    seen_keys = set()
    bad_items = 0
    for n, it in enumerate(items):
        try:
            if not isinstance(it, dict):
                raise Fail("bad_type")
            k = finding_key(it)
        except Fail as e:
            bad_items += 1
            _fail(summary, f"list-item-{n}", e.reason)
            continue
        if k not in seen_keys:
            seen_keys.add(k)
            keys.append(k)
    seen = len(keys) + bad_items
    count404 = 0
    kids = set()
    gone: set = set()

    for key in keys:
        if time.monotonic() - started > opts.deadline_seconds:
            _fail(summary, key, "deadline_exceeded")
            continue
        observed = _iso(_utcnow())
        try:
            detail = api.detail_with_traffic(key)
            if finding_key(detail) != key:
                raise Fail("bad_id")
            claimed = claimed_bodies(detail)
            claimed_record = build_record(detail)
            try:
                head = load_head(findings_dir, key, instance_name)
            except ReceiptInvalid:
                raise Fail("receipt_invalid")
            if head and head.seq and head.kid:
                kids.add(head.kid)
            if head and head.seq and record_hash(claimed_record) == head.inputs_hash:
                if opts.verify_bodies:
                    for (bid, side), (h, ln) in claimed.items():
                        got_h, got_n = api.hash_body(key, bid, side, ln, opts.max_body_bytes)
                        if got_n != ln:
                            raise Fail("length_mismatch")
                        if got_h != h:
                            raise Fail("evidence_hash_mismatch")
                else:
                    summary.unchanged_bodies_not_rechecked += 1
                summary.unchanged += 1
                continue
            computed: Dict[Tuple[str, str], Tuple[str, int]] = {}
            for (bid, side), (h, ln) in claimed.items():
                got_h, got_n = api.hash_body(key, bid, side, ln, opts.max_body_bytes)
                if got_n != ln:
                    raise Fail("length_mismatch")
                if got_h != h:
                    raise Fail("evidence_hash_mismatch")
                computed[(bid, side)] = (got_h, got_n)
            record = build_record(detail, computed)
            seq = (head.seq if head else 0) + 1
            previous = head.inputs_hash if head and head.seq else None
            receipt = mint_finding(record, key, seq, previous, meta, observed)
            d = findings_dir / key
            d.mkdir(mode=0o700, exist_ok=True)
            rec_path = d / f"{seq:06d}.record.json"
            if head and head.orphan_seq:
                with contextlib.suppress(OSError):
                    os.replace(rec_path, d / f"{seq:06d}.record.json.orphan.{_utcnow().strftime('%Y%m%dT%H%M%SZ')}")
            try:
                _atomic_write(rec_path, record.encode("ascii"))
                _atomic_write(d / f"{seq:06d}.receipt.json", json.dumps(receipt, sort_keys=True, indent=1).encode("ascii"))
            except (OSError, UnicodeEncodeError):
                raise Fail("write_failed")
            summary.minted += 1
        except Fail as e:
            if e.status == 404 and e.reason == "http_status":
                count404 += 1
                gone.add(key)
                continue
            _fail(summary, key, e.reason)

    # Second listing: a finding that vanished while we worked, or that has receipts and is no longer listed.
    summary.complete = True
    try:
        final_keys = set()
        for n, it in enumerate(api.list_pages()):
            with contextlib.suppress(Fail):
                final_keys.add(finding_key(it))
    except Fail as e:
        summary.complete = False
        _fail(summary, "*", e.reason)
        final_keys = set(keys)
    gone |= {k for k in keys if k not in final_keys}
    gone |= {k for k in _disk_keys(findings_dir) if k not in final_keys}
    for k in sorted(gone):
        summary.failures.append({"key": k, "reason": "finding_gone"})
    summary.gone = len(gone)

    # Run-level failures ("*") are not tied to a listed finding, so they are not part of `seen`.
    run_level = sum(1 for f in summary.failures if f["key"] == "*")
    if summary.minted + summary.unchanged + summary.failed - run_level + count404 != seen:
        summary.failures.append({"key": "*", "reason": "count_mismatch"})
        summary.failed += 1
    summary.kids_seen = sorted(kids | ({meta.kid} if meta.kid else set()))
    summary.signer_kid = meta.kid or (sorted(kids)[0] if len(kids) == 1 else "")
    summary.pq_signed = meta.pq_all if meta.minted_any else None
    summary.chain_head_sha256 = _chain_head_hash(findings_dir)
    summary.exit_code = 0 if (summary.failed == 0 and summary.gone == 0 and summary.complete) else 1
    return summary


# --------------------------------------------------------------------------- CLI


def _preflight(args: argparse.Namespace) -> Tuple[Path, str, Any]:
    if os.name != "posix":
        raise Preflight("sync needs a POSIX system (it uses flock)")
    key_env = os.environ.get("OAO_RECEIPT_KEY", "")
    if not key_env:
        raise Preflight("OAO_RECEIPT_KEY must be set to the signing key file")
    key_path = Path(key_env)
    if not key_path.exists() and not args.init_key:
        raise Preflight("the signing key file does not exist; pass --init-key to create it")
    srv = _srv()  # imports OAO, which reads OAO_RECEIPT_KEY now
    from openagentontology import receipt as oao_receipt
    if str(Path(str(getattr(oao_receipt, "_DEFAULT_KEY", "")))) != str(key_path):
        raise Preflight("openagentontology was loaded with a different signing key than OAO_RECEIPT_KEY")
    out = Path(args.out)
    if not out.is_absolute():
        raise Preflight("--out must be an absolute path")
    if not _KEY_RE.fullmatch(args.instance_name or ""):
        raise Preflight("--instance-name must be 1-64 characters of letters, digits, _ and -")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    import fcntl
    lock = open(out / ".lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise Preflight("another run holds the lock on --out")
    url = os.environ.get("ARTEX_URL", "http://127.0.0.1:8787").rstrip("/")
    m = re.fullmatch(r"(https?)://([^/:@\s]+)(?::(\d{1,5}))?", url)
    if not m:
        lock.close()
        raise Preflight("ARTEX_URL must look like http(s)://host[:port] with no path or credentials")
    loopback = m.group(2) in ("127.0.0.1", "localhost", "::1")
    if m.group(1) != "https" and not loopback and not args.allow_insecure:
        lock.close()
        raise Preflight("ARTEX_URL is plain http to a non-loopback host; use https or pass --allow-insecure")
    origin = url
    inst_path = out / "INSTANCE"
    stored = None
    if inst_path.exists():
        try:
            stored = strict_loads(inst_path.read_bytes())
        except (ValueError, OSError):
            lock.close()
            raise Preflight("INSTANCE file is unreadable")
    new = {"instance_name": args.instance_name, "url_origin": origin}
    if stored is None:
        _atomic_write(inst_path, canonical(new).encode("ascii"))
    elif stored != new:
        if not args.rebind:
            lock.close()
            raise Preflight("instance name or ARTEX origin differs from the one stored in OUT/INSTANCE; pass --rebind")
        stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
        _atomic_write(out / f"REBIND.{stamp}", canonical({"old": stored, "new": new}).encode("ascii"))
        _atomic_write(inst_path, canonical(new).encode("ascii"))
    return out, origin, lock


def _password() -> str:
    pf = os.environ.get("ARTEX_PASSWORD_FILE")
    if pf:
        try:
            return Path(pf).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError:
            raise Preflight("ARTEX_PASSWORD_FILE could not be read")
    pw = os.environ.get("ARTEX_PASSWORD")
    if not pw:
        raise Preflight("ARTEX_PASSWORD (or ARTEX_PASSWORD_FILE) must be set")
    return pw


def _cmd_sync(args: argparse.Namespace) -> int:
    for k in args.ack_gone:
        if not _KEY_RE.fullmatch(k):
            print(json.dumps({"error": "--ack-gone needs a finding key"}), file=sys.stderr)
            return 2
    try:
        out, origin, lock = _preflight(args)
        username = os.environ.get("ARTEX_USERNAME", "")
        if not username:
            raise Preflight("ARTEX_USERNAME must be set")
        password = _password()
    except Preflight as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 3
    try:
        client = _client_factory(30.0)
        api = ArtexApi(client, origin)
        try:
            api.login(username, password)
        except Fail as e:
            print(json.dumps({"complete": False, "failures": [{"key": "*", "reason": e.reason}]}))
            return 1
        opts = Options(max_body_bytes=args.max_body_bytes, verify_bodies=args.verify_bodies, rebind=args.rebind,
                       ack_gone=tuple(args.ack_gone))
        summary = sync(api, out, args.instance_name, origin, opts)
        print(json.dumps(summary.as_json(), sort_keys=True))
        with contextlib.suppress(Exception):
            client.close()
        return summary.exit_code
    finally:
        lock.close()


def _cmd_verify(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        _srv()
    except Preflight as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 3
    if args.chain:
        if args.receipt or args.record:
            parser.error("verify --chain takes no RECEIPT or RECORD")
        res = verify_chain(Path(args.chain), args.kid, allow_origin_change=args.allow_origin_change,
                           require_pq=args.require_pq)
        print(json.dumps(res, sort_keys=True))
        return 0 if res["ok"] else 1
    if not (args.receipt and args.record):
        parser.error("verify needs RECEIPT and RECORD, or --chain DIR")
    try:
        r = verify_pair(Path(args.receipt).read_bytes(), Path(args.record).read_bytes(), kid=args.kid,
                        require_pq=args.require_pq)
    except OSError:
        print(json.dumps({"ok": False, "reason": "receipt or record could not be read"}))
        return 1
    print(json.dumps(r.as_json(), sort_keys=True))
    return 0 if r.ok else 1


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trust-gate-artex", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync", help="sign a receipt for every new or changed ARTEX finding")
    s.add_argument("--out", required=True, help="absolute path of the output directory (local disk)")
    s.add_argument("--instance-name", required=True, help="a stable label for this ARTEX deployment")
    s.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY)
    s.add_argument("--verify-bodies", action="store_true", help="also re-hash the bodies of unchanged findings")
    s.add_argument("--init-key", action="store_true", help="allow OAO to create the signing key if it is absent")
    s.add_argument("--allow-insecure", action="store_true", help="allow plain http to a non-loopback ARTEX")
    s.add_argument("--rebind", action="store_true", help="accept a changed instance name or ARTEX origin")
    s.add_argument("--ack-gone", action="append", default=[], metavar="KEY",
                   help="a finding deleted in ARTEX on purpose; stop reporting it")
    v = sub.add_parser("verify", help="verify a receipt and its record, or a whole OUT directory")
    v.add_argument("receipt", nargs="?")
    v.add_argument("record", nargs="?")
    v.add_argument("--chain", metavar="DIR")
    v.add_argument("--kid", required=True, help="the 32-hex kid of the signing key you trust")
    v.add_argument("--allow-origin-change", action="store_true")
    g = v.add_mutually_exclusive_group()
    g.add_argument("--require-pq", dest="require_pq", action="store_true", default=None)
    g.add_argument("--no-require-pq", dest="require_pq", action="store_false")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.cmd == "sync":
        return _cmd_sync(args)
    return _cmd_verify(args, parser)


if __name__ == "__main__":
    sys.exit(main())
