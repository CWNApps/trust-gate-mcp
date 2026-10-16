"""api_ops.py -- read-only views over a Trust Gate API deployment you run or subscribe to.

These tools are OPT-IN. They do nothing until the operator sets three environment variables:

  TRUST_GATE_API_URL     base URL of the Trust Gate API (https; http only for localhost)
  TRUST_GATE_API_KEY     bearer credential issued for ONE tenant
  TRUST_GATE_TENANT_ID   that tenant's id

Rules every call follows:

  * Read-only. A call never writes, signs, executes or authorizes anything. The API answers from
    the records the caller supplies.
  * The tenant comes from configuration. A model-supplied argument that names a tenant is refused,
    and the configured tenant is the only one ever sent.
  * Fail closed. A missing setting, a 404 (the surface is off or not deployed), a rate limit, a
    server error, a transport error or an answer of the wrong shape all become a typed
    UNAVAILABLE result. Nothing is ever filled in, defaulted or invented.
  * The credential is never logged, echoed or placed in an error. No exception text is returned.
  * A mapping or a readout is a view of what the caller supplied. It is not a compliance finding.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

NOTICE = ("Read-only view of the records you supplied. Nothing was written, signed, executed or authorized. "
          "A mapping or readout is not a compliance finding.")

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 10.0

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_TENANT_KEYS = ("tenant_id", "tenant", "tenantId")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

# One row per tool: (path, send the configured tenant in the body, response field to return or None for the whole answer).
_OA = "/internal/outcome-harness/operator-assurance"
_SI = "/internal/signal-intel"
OPERATIONS: Dict[str, Dict[str, Any]] = {
    "inspect_oversight_case": {"path": _OA + "/readiness", "body_tenant": False, "field": "report"},
    "propose_role_question": {"path": _OA + "/questions", "body_tenant": False, "field": None},
    "get_intervention_evidence": {"path": _OA + "/readiness", "body_tenant": False, "field": "pause"},
    "compare_qualification_change": {"path": _SI + "/requalification/status", "body_tenant": True, "field": None},
    "export_acceptance_pack": {"path": _OA + "/acceptance-pack", "body_tenant": False, "field": None},
    "get_receipt_evidence": {"path": _SI + "/evidence/receipt", "body_tenant": True, "field": None},
    "get_decision_evidence": {"path": _SI + "/evidence/decision", "body_tenant": True, "field": None},
    "replay_decision": {"path": _SI + "/replay", "body_tenant": True, "field": None},
    "propose_requalification": {"path": _SI + "/propose", "body_tenant": True, "field": None},
}


def _client_factory(timeout: float):
    """The HTTP client. Tests replace this with one on a mocked transport."""
    import httpx
    return httpx.Client(timeout=timeout, follow_redirects=False)


def _unavailable(op: str, reason: str) -> Dict[str, Any]:
    return {"status": "UNAVAILABLE", "operation": op, "reason": reason, "read_only": True, "data": None, "notice": NOTICE}


def _refused(op: str, reason: str, code: Optional[str] = None) -> Dict[str, Any]:
    out = {"status": "REFUSED", "operation": op, "reason": reason, "read_only": True, "data": None, "notice": NOTICE}
    if code is not None:
        out["code"] = code
    return out


def _config():
    """(base_url, key, tenant) or (None, reason). The key is read here and goes nowhere but the header."""
    base = os.environ.get("TRUST_GATE_API_URL", "").strip()
    key = os.environ.get("TRUST_GATE_API_KEY", "").strip()
    tenant = os.environ.get("TRUST_GATE_TENANT_ID", "").strip()
    if not base or not key or not tenant:
        return None, "not_configured"
    if not _TENANT_RE.match(tenant):
        return None, "tenant_setting_invalid"
    parts = urlsplit(base)
    host = (parts.hostname or "").lower()
    ok_scheme = parts.scheme == "https" or (parts.scheme == "http" and host in _LOCAL_HOSTS)
    if not ok_scheme or not host or parts.username or parts.password or parts.query or parts.fragment:
        return None, "url_setting_invalid"
    return (base.rstrip("/"), key, tenant), None


def _code_from(resp) -> Optional[str]:
    """A short error code from an error body, or None. Never free text."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - any parse failure means no code
        return None
    if not isinstance(body, dict):
        return None
    cand = body.get("code")
    if cand is None and isinstance(body.get("detail"), dict):
        cand = body["detail"].get("code")
    return cand if isinstance(cand, str) and _CODE_RE.match(cand) else None


def call(op: str, request: Any) -> Dict[str, Any]:
    """Run one read-only operation. Always returns a dict with a typed `status`: OK, REFUSED or UNAVAILABLE."""
    spec = OPERATIONS.get(op)
    if spec is None:
        return _refused(op, "unknown_operation")
    if not isinstance(request, dict) or not request:
        return _refused(op, "request_must_be_a_non_empty_object")
    if any(k in request for k in _TENANT_KEYS):
        return _refused(op, "tenant_is_configuration_not_an_argument")
    cfg, why = _config()
    if cfg is None:
        return _unavailable(op, why)
    base, key, tenant = cfg
    body = dict(request)
    if spec["body_tenant"]:
        body["tenant_id"] = tenant
    try:
        raw = json.dumps(body, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return _refused(op, "request_not_json_serialisable")
    if len(raw) > MAX_REQUEST_BYTES:
        return _refused(op, "request_too_large")
    headers = {"Authorization": "Bearer " + key, "X-CWN-Tenant-Id": tenant,
               "Content-Type": "application/json", "Accept": "application/json"}
    try:
        with _client_factory(TIMEOUT_SECONDS) as client:
            resp = client.post(base + spec["path"], content=raw, headers=headers)
    except Exception:  # noqa: BLE001 - never return exception text (it can carry the URL)
        return _unavailable(op, "transport_error")
    status = resp.status_code
    if status == 404:
        return _unavailable(op, "surface_not_available")
    if status == 429 or status >= 500:
        return _unavailable(op, "service_unavailable")
    if status != 200:
        return _refused(op, "api_refused", _code_from(resp))
    if len(resp.content) > MAX_RESPONSE_BYTES:
        return _unavailable(op, "response_too_large")
    try:
        answer = resp.json()
    except Exception:  # noqa: BLE001
        return _unavailable(op, "response_not_json")
    if not isinstance(answer, dict):
        return _unavailable(op, "response_wrong_shape")
    field = spec["field"]
    if field is not None:
        if field not in answer:
            return _unavailable(op, "response_wrong_shape")
        data = {field: answer[field]}
        for carry in ("overall", "trust_basis", "mode", "can_write", "can_execute"):
            if carry in answer:
                data[carry] = answer[carry]
    else:
        data = answer
    return {"status": "OK", "operation": op, "read_only": True, "data": data, "notice": NOTICE}


def make_tool(op: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def tool(request: Dict[str, Any]) -> Dict[str, Any]:
        return call(op, request)
    tool.__name__ = op
    return tool
