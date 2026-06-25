"""server_http.py -- the Streamable HTTP entrypoint for Smithery container deploy.

Per Smithery's container-runtime contract: the server must speak MCP Streamable HTTP on a
`/mcp` path and listen on the `PORT` env var (Smithery sets PORT=8081). The FastMCP runtime
ships a streamable_http_app() builder we mount under /mcp.

This file is the deploy adapter only -- all four tools live in server.py and the receipt
primitive is unchanged. Local dev still uses `python server.py` (stdio).
"""
from __future__ import annotations

import os
import sys

from auth import BearerAuthMiddleware, _allowed_origins, auth_active
from bootstrap import ensure_keys_and_metadata
from rate_limit import RateLimitMiddleware
from server import build_server


def main() -> None:
    import uvicorn  # only needed for the HTTP transport
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import Mount

    # Ensure the persistent signing key + metadata exist BEFORE we accept any traffic.
    # Aborts (exit 78) if the on-disk metadata's kid mismatches the live key -- a silent
    # mismatch would invalidate every receipt chain.
    meta = ensure_keys_and_metadata()
    print(f"[server_http] notary kid={meta.get('kid')} algs={meta.get('algorithms')}",
          file=sys.stderr)

    mcp_server = build_server()

    # CORS posture follows the bearer-auth toggle:
    #   bearer off  -> allow_origins=['*'] (verify-as-public-good adoption path)
    #   bearer on   -> allow_origins from TRUST_GATE_ALLOWED_ORIGINS (no '*' with credentials)
    allowed = _allowed_origins()
    auth_on = auth_active()
    print(f"[server_http] bearer_auth={'ON' if auth_on else 'OFF'} "
          f"cors_origins={allowed}", file=sys.stderr)

    # FastMCP -> Streamable HTTP app, mounted at /mcp per the Smithery contract.
    app = Starlette(
        routes=[Mount("/mcp", app=mcp_server.streamable_http_app())],
        middleware=[
            # CORS first so preflight passes before any auth check sees it.
            Middleware(CORSMiddleware, allow_origins=allowed,
                       allow_methods=["*"], allow_headers=["*"], expose_headers=["*"],
                       allow_credentials=auth_on),
            # Optional bearer auth -- no-op unless TRUST_GATE_BEARER_TOKEN is set.
            Middleware(BearerAuthMiddleware),
            # Per-IP token-bucket rate-limit. Defaults: 60 mint/min, 600 verify/min,
            # 120 default/min. Override via RATE_LIMIT_* env. Per-pod (documented in
            # PUBLISH.md); behind Smithery's gateway this is correct for v1.
            Middleware(RateLimitMiddleware),
        ],
    )
    port = int(os.environ.get("PORT", "8081"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
