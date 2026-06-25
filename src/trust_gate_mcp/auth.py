"""auth.py -- optional bearer-token middleware for the Streamable HTTP entrypoint.

Off by default (preserves the "verify is a public good" stance: anyone with a receipt can
verify it). When TRUST_GATE_BEARER_TOKEN is set:

  - Every request must carry `Authorization: Bearer <token>` matching the env value.
  - The matching CORS allowlist (TRUST_GATE_ALLOWED_ORIGINS, comma-separated) replaces the
    permissive `*` -- since credentials are now in play, wide CORS would be unsafe.

This sits in front of FastMCP's HTTP app, so it applies to every JSON-RPC call equally."""
from __future__ import annotations

import hmac
import os
from typing import Awaitable, Callable, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def _required_token() -> str:
    return os.environ.get("TRUST_GATE_BEARER_TOKEN", "").strip()


def _allowed_origins() -> List[str]:
    """If bearer-auth is ON: parse TRUST_GATE_ALLOWED_ORIGINS (comma-separated). If OFF
    or unset: return ['*'] so the public-good adoption path stays open."""
    if not _required_token():
        return ["*"]
    raw = os.environ.get("TRUST_GATE_ALLOWED_ORIGINS", "").strip()
    if not raw:
        # bearer-auth is on but no allowlist set -- refuse '*' implicitly. Empty list means
        # CORS denies everything except same-origin; the operator must set the allowlist.
        return []
    return [o.strip() for o in raw.split(",") if o.strip()]


def auth_active() -> bool:
    """True iff TRUST_GATE_BEARER_TOKEN is set -- callers use this to wire CORS."""
    return bool(_required_token())


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Constant-time bearer-token check. No-op when TRUST_GATE_BEARER_TOKEN is unset."""

    async def dispatch(self, request: Request,
                       call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        required = _required_token()
        if not required:
            return await call_next(request)
        # CORS preflight must pass through so the browser can learn the policy.
        if request.method == "OPTIONS":
            return await call_next(request)
        hdr = request.headers.get("authorization", "")
        if not hdr.lower().startswith("bearer "):
            return JSONResponse({"error": "unauthorized",
                                 "message": "Authorization: Bearer <token> required"},
                                status_code=401)
        # Constant-time compare -- a timing oracle on a 32-char token is recoverable.
        presented = hdr.split(" ", 1)[1].strip()
        if not hmac.compare_digest(presented, required):
            return JSONResponse({"error": "unauthorized",
                                 "message": "bearer token mismatch"}, status_code=401)
        return await call_next(request)
