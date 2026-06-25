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
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    # Ensure the persistent signing key + metadata exist BEFORE we accept any traffic.
    # Aborts (exit 78) if the on-disk metadata's kid mismatches the live key -- a silent
    # mismatch would invalidate every receipt chain.
    meta = ensure_keys_and_metadata()
    print(f"[server_http] notary kid={meta.get('kid')} algs={meta.get('algorithms')}",
          file=sys.stderr)

    mcp_server = build_server()

    # Static server card so a directory/scanner that cannot complete a Streamable HTTP
    # handshake (e.g. behind a strict redirect, behind an auth wall, etc.) can still
    # learn the server's identity + tool surface. Documented at
    # https://smithery.ai/docs/build/publish (Static Server Card section).
    SERVER_CARD = {
        "schemaVersion": "v1",
        "name": "trust-gate",
        "version": "0.2.0",
        "description": ("Post-quantum, tamper-evident receipts for consequential agent "
                        "actions. Four tools, one shared post-quantum primitive (Ed25519 + "
                        "ML-DSA-65 + SLH-DSA via OpenAgentOntology). Verifiable offline."),
        "homepage": "https://github.com/CWNApps/trust-gate-mcp",
        "license": "Apache-2.0",
        "tools": [
            {"name": "mint_receipt_for_record_change",
             "description": ("Mint a post-quantum receipt for one CRM record change. Old/new "
                             "values are SHA-256 hashes. Works with any CRM.")},
            {"name": "audit_my_agent_inventory",
             "description": ("Rank a CALLER-PROVIDED list of MCP tools by worst-regret if "
                             "they act. Read-only. Cannot auto-discover other servers "
                             "(MCP protocol does not allow that).")},
            {"name": "mint_action_receipt",
             "description": "Mint a post-quantum receipt for any consequential agent action."},
            {"name": "verify_receipt",
             "description": ("Verify a Trust Gate receipt from the certificate alone (offline). "
                             "Defaults to PQ-required mode -- defends against signature stripping.")},
        ],
    }

    async def server_card(_request):
        return JSONResponse(SERVER_CARD)

    # CORS posture follows the bearer-auth toggle:
    #   bearer off  -> allow_origins=['*'] (verify-as-public-good adoption path)
    #   bearer on   -> allow_origins from TRUST_GATE_ALLOWED_ORIGINS (no '*' with credentials)
    allowed = _allowed_origins()
    auth_on = auth_active()
    print(f"[server_http] bearer_auth={'ON' if auth_on else 'OFF'} "
          f"cors_origins={allowed}", file=sys.stderr)

    # FastMCP -> Streamable HTTP app, mounted at /mcp per the Smithery contract.
    # Static server card at /.well-known/mcp/server-card.json lets directory scanners
    # learn the tool surface without completing a Streamable HTTP handshake.
    app = Starlette(
        routes=[
            Route("/.well-known/mcp/server-card.json", server_card, methods=["GET"]),
            Mount("/mcp", app=mcp_server.streamable_http_app()),
        ],
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
