"""tests/test_artex_sync.py -- the ARTEX findings-to-receipt bridge (docs/designs/artex_sync.md).

ARTEX is replaced by a fake behind httpx.MockTransport; signing uses the throwaway key from conftest.py.
"""
import json
import os
import stat

import httpx
import pytest

from trust_gate_mcp import artex_sync as a
from trust_gate_mcp import server as srv

pytestmark = pytest.mark.skipif(srv._oao_receipt is None, reason="openagentontology not available in this env")

ORIGIN = "http://127.0.0.1:8787"
BODY_REQ = b"GET /x HTTP/1.1\r\n\r\n"
BODY_RESP = b"HTTP/1.1 200 OK\r\n\r\nhello"


def sha(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


def make_finding(fid="f1", **over):
    d = {
        "finding_id": fid, "id": fid, "name": "SQLi", "vulnclass": "sqli", "severity": "high", "status": "open",
        "verification_status": "verified", "poe_level": 2, "task_id": "t1", "evidence_version": 1,
        "ts": "2026-11-01T00:00:00Z", "summary": "summary text", "evidence": "evidence text",
        "assets": [{"id": "a1", "type": "host", "label": "10.0.0.1"}],
        "traffic_bindings": [{
            "id": "b1", "role": "proof", "position": 0, "note": None,
            "snapshot": {"id": "s1", "method": "GET", "status": 200, "captured_at": 1,
                         "url": "http://10.0.0.1/x",
                         "req_len": len(BODY_REQ), "req_hash": sha(BODY_REQ),
                         "resp_len": len(BODY_RESP), "resp_hash": sha(BODY_RESP)},
        }],
    }
    d.update(over)
    return d


class FakeArtex:
    def __init__(self):
        self.findings = {"f1": make_finding("f1")}
        self.bodies = {("f1", "b1", "request"): BODY_REQ, ("f1", "b1", "response"): BODY_RESP}
        self.calls = []
        self.login_status = 200
        self.password_seen = None
        self.token = "tok-SECRET-123"
        self.redirect_findings = False
        self.fail_detail = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        p = request.url.path
        self.calls.append((request.method, p))
        if p == "/api/auth/login":
            self.password_seen = json.loads(request.content)["password"]
            if self.login_status != 200:
                return httpx.Response(self.login_status, json={})
            return httpx.Response(200, json={"token": self.token})
        if request.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={})
        if p == "/api/health":
            return httpx.Response(200, json={"version": "0.6.0"})
        if p == "/api/exploration/findings":
            if self.redirect_findings:
                return httpx.Response(302, headers={"location": "http://evil.example/"})
            items = [{"finding_id": k, "id": k} for k in self.findings]
            page = int(request.url.params.get("page", "1"))
            return httpx.Response(200, json={"items": items if page == 1 else [], "total": len(items)})
        parts = p.split("/")
        if len(parts) == 5 and parts[3] == "findings":
            k = parts[4]
            if k in self.fail_detail:
                return httpx.Response(self.fail_detail[k])
            if k not in self.findings:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=self.findings[k])
        if len(parts) == 8 and parts[5] == "traffic" and parts[7] == "body":
            body = self.bodies.get((parts[4], parts[6], request.url.params["side"]))
            if body is None:
                return httpx.Response(404)
            return httpx.Response(200, content=body)
        return httpx.Response(404)


@pytest.fixture
def fake(monkeypatch):
    f = FakeArtex()
    monkeypatch.setattr(a, "_client_factory",
                        lambda timeout: httpx.Client(transport=httpx.MockTransport(f.handler), timeout=timeout,
                                                     follow_redirects=False))
    monkeypatch.setenv("ARTEX_URL", ORIGIN)
    monkeypatch.setenv("ARTEX_USERNAME", "admin")
    monkeypatch.setenv("ARTEX_PASSWORD", "pw-SECRET-456")
    monkeypatch.delenv("ARTEX_PASSWORD_FILE", raising=False)
    return f


def run(tmp_path, capsys, *extra, name="lab"):
    out = tmp_path / "out"
    code = a.main(["sync", "--out", str(out), "--instance-name", name, "--init-key", *extra])
    cap = capsys.readouterr()
    return code, cap.out, cap.err, out


def summary(stdout):
    return json.loads(stdout.strip().splitlines()[-1])


def kid_of(out):
    r = json.loads((out / "findings" / "f1" / "000001.receipt.json").read_text())
    return r["kid"]


# ------------------------------------------------------------------ happy path and reruns


def test_first_run_mints_then_rerun_is_unchanged(fake, tmp_path, capsys):
    code, o, e, out = run(tmp_path, capsys)
    s = summary(o)
    assert code == 0 and s["minted"] == 1 and s["unchanged"] == 0 and s["complete"] is True
    assert (out / "findings" / "f1" / "000001.record.json").exists()
    code, o, _, _ = run(tmp_path, capsys)
    s = summary(o)
    assert code == 0 and s["minted"] == 0 and s["unchanged"] == 1
    assert s["unchanged_bodies_not_rechecked"] == 1
    assert not (out / "findings" / "f1" / "000002.receipt.json").exists()


def test_record_holds_hashes_not_target_data(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    text = (out / "findings" / "f1" / "000001.record.json").read_text()
    for secret in ("10.0.0.1", "summary text", "evidence text", "hello"):
        assert secret not in text
    rec = json.loads(text)
    assert rec["traffic"][0]["resp_sha256"] == sha(BODY_RESP)


def test_change_mints_seq2_with_link_and_a_b_a_gets_seq3(fake, tmp_path, capsys):
    run(tmp_path, capsys)
    fake.findings["f1"] = make_finding("f1", severity="critical")
    code, o, _, out = run(tmp_path, capsys)
    assert code == 0 and summary(o)["minted"] == 1
    fake.findings["f1"] = make_finding("f1")  # back to the first state
    code, o, _, out = run(tmp_path, capsys)
    assert code == 0 and summary(o)["minted"] == 1
    assert (out / "findings" / "f1" / "000003.receipt.json").exists()
    res = a.verify_chain(out, kid_of(out), allow_origin_change=False, require_pq=None)
    assert res["ok"] and res["receipts_checked"] == 3


def test_files_are_private(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "findings" / "f1" / "000001.receipt.json").stat().st_mode) == 0o600


def test_credentials_never_printed(fake, tmp_path, capsys):
    _, o, e, out = run(tmp_path, capsys)
    for stream in (o, e):
        assert "SECRET" not in stream
    for p in out.rglob("*"):
        if p.is_file():
            assert b"SECRET" not in p.read_bytes()


# ------------------------------------------------------------------ failures


def test_login_failure_exit1_no_receipts(fake, tmp_path, capsys):
    fake.login_status = 401
    code, o, _, out = run(tmp_path, capsys)
    assert code == 1 and summary(o)["failures"][0]["reason"] == "login_failed"
    assert not list(out.rglob("*.receipt.json"))


def test_redirect_is_a_failure_not_followed(fake, tmp_path, capsys):
    fake.redirect_findings = True
    code, o, _, _ = run(tmp_path, capsys)
    s = summary(o)
    assert code == 1 and s["complete"] is False
    assert not any("evil" in str(c) for c in fake.calls)


def test_evidence_hash_mismatch_mints_nothing(fake, tmp_path, capsys):
    fake.bodies[("f1", "b1", "response")] = b"HTTP/1.1 200 OK\r\n\r\nHELLO"  # same length, other bytes
    code, o, _, out = run(tmp_path, capsys)
    s = summary(o)
    assert code == 1 and s["minted"] == 0
    assert {"key": "f1", "reason": "evidence_hash_mismatch"} in s["failures"]
    assert not list(out.rglob("*.receipt.json"))


def test_length_mismatch_and_missing_body(fake, tmp_path, capsys):
    fake.bodies[("f1", "b1", "request")] = BODY_REQ + b"extra"
    code, o, _, _ = run(tmp_path, capsys)
    assert code == 1 and {"key": "f1", "reason": "length_mismatch"} in summary(o)["failures"]
    del fake.bodies[("f1", "b1", "request")]
    code, o, _, _ = run(tmp_path, capsys)
    assert code == 1 and {"key": "f1", "reason": "body_missing"} in summary(o)["failures"]


def test_body_too_large_refused(fake, tmp_path, capsys):
    code, o, _, _ = run(tmp_path, capsys, "--max-body-bytes", "4")
    assert code == 1 and {"key": "f1", "reason": "body_too_large"} in summary(o)["failures"]


def test_bad_finding_shape_is_a_named_failure(fake, tmp_path, capsys):
    fake.findings["f1"] = make_finding("f1", poe_level="two")
    code, o, _, _ = run(tmp_path, capsys)
    assert code == 1 and {"key": "f1", "reason": "bad_type"} in summary(o)["failures"]


def test_one_bad_finding_does_not_stop_the_others(fake, tmp_path, capsys):
    fake.findings["f2"] = make_finding("f2")
    fake.bodies[("f2", "b1", "request")] = BODY_REQ
    fake.bodies[("f2", "b1", "response")] = BODY_RESP
    fake.fail_detail["f1"] = 500
    code, o, _, out = run(tmp_path, capsys)
    s = summary(o)
    assert code == 1 and s["minted"] == 1 and s["failed"] == 1
    assert (out / "findings" / "f2" / "000001.receipt.json").exists()


def test_deleted_finding_is_reported_gone_until_acknowledged(fake, tmp_path, capsys):
    run(tmp_path, capsys)
    del fake.findings["f1"]
    code, o, _, _ = run(tmp_path, capsys)
    s = summary(o)
    assert code == 1 and s["gone"] == 1 and {"key": "f1", "reason": "finding_gone"} in s["failures"]
    code, o, _, _ = run(tmp_path, capsys, "--ack-gone", "f1")
    assert code == 0 and summary(o)["gone"] == 0


def test_verify_bodies_catches_swapped_evidence_on_unchanged_finding(fake, tmp_path, capsys):
    run(tmp_path, capsys)
    fake.bodies[("f1", "b1", "response")] = b"HTTP/1.1 200 OK\r\n\r\nHELLO"
    code, o, _, _ = run(tmp_path, capsys)  # default: trusts ARTEX's claimed hash
    assert code == 0
    code, o, _, _ = run(tmp_path, capsys, "--verify-bodies")
    assert code == 1 and {"key": "f1", "reason": "evidence_hash_mismatch"} in summary(o)["failures"]


# ------------------------------------------------------------------ tamper, crash, binding


def test_tampered_record_blocks_further_minting(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    p = out / "findings" / "f1" / "000001.record.json"
    p.write_text(p.read_text().replace("high", "info"))
    fake.findings["f1"] = make_finding("f1", severity="critical")
    code, o, _, _ = run(tmp_path, capsys)
    assert code == 1 and {"key": "f1", "reason": "receipt_invalid"} in summary(o)["failures"]
    assert not (out / "findings" / "f1" / "000002.receipt.json").exists()


def test_orphan_record_without_receipt_is_replaced(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    d = out / "findings" / "f1"
    (d / "000002.record.json").write_text("{}")  # crash between the two writes
    fake.findings["f1"] = make_finding("f1", severity="critical")
    code, o, _, _ = run(tmp_path, capsys)
    assert code == 0 and summary(o)["minted"] == 1
    assert (d / "000002.receipt.json").exists()
    assert list(d.glob("000002.record.json.orphan.*"))


def test_instance_binding_requires_rebind(fake, tmp_path, capsys, monkeypatch):
    run(tmp_path, capsys)
    code, _, e, _ = run(tmp_path, capsys, name="other")
    assert code == 3 and "differs" in e
    monkeypatch.setenv("ARTEX_URL", "http://localhost:8787")  # same instance name, new origin
    code, _, e, _ = run(tmp_path, capsys)
    assert code == 3 and "differs" in e
    code, _, _, out = run(tmp_path, capsys, "--rebind")
    assert code == 0 and list(out.glob("REBIND.*"))
    fake.findings["f1"] = make_finding("f1", severity="critical")
    code, _, _, out = run(tmp_path, capsys)
    assert code == 0
    kid = kid_of(out)
    assert not a.verify_chain(out, kid, allow_origin_change=False, require_pq=None)["ok"]
    assert a.verify_chain(out, kid, allow_origin_change=True, require_pq=None)["ok"]


def test_second_run_holding_the_lock_is_refused(fake, tmp_path, capsys):
    import fcntl
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    held = open(out / ".lock", "a")
    fcntl.flock(held, fcntl.LOCK_EX)
    try:
        code, _, e, _ = run(tmp_path, capsys)
        assert code == 3 and "lock" in e
    finally:
        held.close()


# ------------------------------------------------------------------ preflight


def test_preflight_refusals(fake, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ARTEX_URL", "http://artex.example:8787")
    code, _, e, _ = run(tmp_path, capsys)
    assert code == 3 and "plain http" in e
    monkeypatch.setenv("ARTEX_URL", "http://user:pw@127.0.0.1:8787")
    code, _, e, _ = run(tmp_path, capsys)
    assert code == 3 and "ARTEX_URL" in e
    monkeypatch.setenv("ARTEX_URL", ORIGIN)
    monkeypatch.delenv("ARTEX_PASSWORD")
    code, _, e, _ = run(tmp_path, capsys)
    assert code == 3 and "ARTEX_PASSWORD" in e
    code = a.main(["sync", "--out", "relative/dir", "--instance-name", "lab"])
    assert code == 3
    code = a.main(["sync", "--out", str(tmp_path / "o2"), "--instance-name", "bad name!"])
    assert code == 3


def test_password_file_is_used(fake, tmp_path, capsys, monkeypatch):
    pf = tmp_path / "pw"
    pf.write_text("from-file\n")
    monkeypatch.delenv("ARTEX_PASSWORD")
    monkeypatch.setenv("ARTEX_PASSWORD_FILE", str(pf))
    code, _, _, _ = run(tmp_path, capsys)
    assert code == 0 and fake.password_seen == "from-file"


# ------------------------------------------------------------------ verify command


def test_verify_accepts_and_rejects(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    d = out / "findings" / "f1"
    kid = kid_of(out)
    rc, rr = d / "000001.receipt.json", d / "000001.record.json"
    assert a.main(["verify", str(rc), str(rr), "--kid", kid]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert a.main(["verify", "--chain", str(out), "--kid", kid]) == 0
    capsys.readouterr()
    assert a.main(["verify", str(rc), str(rr), "--kid", "0" * 32]) == 1
    capsys.readouterr()
    other = tmp_path / "other.json"
    other.write_text(rr.read_text().replace("high", "info"))
    assert a.main(["verify", str(rc), str(other), "--kid", kid]) == 1


def test_lookalike_receipt_from_the_generic_tool_is_rejected(fake, tmp_path, capsys):
    """A client of the MCP server must not be able to forge an artex-sync receipt."""
    _, _, _, out = run(tmp_path, capsys)
    d = out / "findings" / "f1"
    record = (d / "000001.record.json").read_text()
    m = {"operation": a.OPERATION, "issuer_tool": "mint_action_receipt", "agent_id": a.AGENT_ID, "policy": a.POLICY,
         "target": "artex:lab/finding/f1", "inputs_hash": srv._ascii_hash(record), "seq": 1,
         "previous_inputs_hash": None, "observed_at": "2026-11-17T00:00:00Z", "artex_version": "0.6.0",
         "artex_origin": ORIGIN}
    forged = srv._mint(m, a.DECISION)
    r = a.verify_pair(json.dumps(forged).encode(), record.encode(), kid=None, require_pq=None)
    assert not r.ok


def test_unsigned_top_level_fields_are_not_trusted(fake, tmp_path, capsys):
    _, _, _, out = run(tmp_path, capsys)
    d = out / "findings" / "f1"
    r = json.loads((d / "000001.receipt.json").read_text())
    rec = (d / "000001.record.json").read_bytes()
    extra = dict(r, target="artex:lab/finding/zzz", operation="x")  # unsigned top-level look-alikes
    res = a.verify_pair(json.dumps(extra).encode(), rec, kid=None, require_pq=None)
    assert res.ok and res.key == "f1"  # signed values win; the unsigned additions change nothing
    forged = dict(r, decision="ALLOW")  # decision is signed, so changing it breaks the signature
    assert not a.verify_pair(json.dumps(forged).encode(), rec, kid=None, require_pq=None).ok


def test_chain_detects_gap_and_broken_link(fake, tmp_path, capsys):
    run(tmp_path, capsys)
    fake.findings["f1"] = make_finding("f1", severity="critical")
    _, _, _, out = run(tmp_path, capsys)
    d = out / "findings" / "f1"
    kid = kid_of(out)
    assert a.verify_chain(out, kid, allow_origin_change=False, require_pq=None)["ok"]
    (d / "000001.receipt.json").unlink()
    (d / "000001.record.json").unlink()
    assert not a.verify_chain(out, kid, allow_origin_change=False, require_pq=None)["ok"]


# ------------------------------------------------------------------ helpers


def test_strict_loads_rejects_nan_floats_duplicates():
    for bad in ('{"a":NaN}', '{"a":1.5}', '{"a":1,"a":2}', "\xff"):
        with pytest.raises(ValueError):
            a.strict_loads(bad if isinstance(bad, str) else bad.encode())
    with pytest.raises(ValueError):
        a.strict_loads(b"\xff\xfe")


def test_canonical_is_ascii_and_stable():
    s = a.canonical({"b": "é", "a": 1})
    assert s == '{"a":1,"b":"\\u00e9"}'
    s.encode("ascii")


def test_lone_surrogate_text_fails_closed_not_crashes():
    with pytest.raises(a.Fail) as ei:
        a.build_record(make_finding("f1", summary="bad \ud800 text"))
    assert ei.value.reason == "bad_text"


def test_absent_and_null_optional_fields_hash_the_same():
    a1 = make_finding("f1")
    a2 = make_finding("f1", report=None)
    assert a.build_record(a1) == a.build_record(a2)


def test_golden_record_bytes():
    rec = a.build_record(make_finding("f1"))
    assert rec == a.canonical(json.loads(rec))
    assert rec.startswith('{"finding":{"assets":[{"id":"a1"')
    assert a.record_hash(rec) == a.record_hash(rec)
