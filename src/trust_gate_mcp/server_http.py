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
    from starlette.responses import HTMLResponse, JSONResponse
    from starlette.routing import Mount, Route

    # Ensure the persistent signing key + metadata exist BEFORE we accept any traffic.
    # Aborts (exit 78) if the on-disk metadata's kid mismatches the live key -- a silent
    # mismatch would invalidate every receipt chain.
    meta = ensure_keys_and_metadata()
    print(f"[server_http] notary kid={meta.get('kid')} algs={meta.get('algorithms')}",
          file=sys.stderr)

    mcp_server = build_server()

    # FastMCP's streamable_http_app initializes its session-manager task group inside its
    # OWN lifespan. If we wrap it under a NEW Starlette without forwarding the lifespan,
    # the manager never starts and every request fails with
    #   RuntimeError: Task group is not initialized. Make sure to use run().
    # Forward it explicitly.
    inner_mcp_app = mcp_server.streamable_http_app()

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

    # Telemetry endpoint for agentic-distribution attribution.
    # Each external listing/PR uses ?via=<channel> on its trust-gate-mcp link.
    # When a human or agent lands on the page (or follows a link), the landing-page
    # JS pings /x with the channel + kind, and /x logs ONE line to stderr (which
    # Render captures + lets us aggregate per-channel). No DB, no IPs, no cookies --
    # just channel + UA family + kind. Privacy-respecting by design.
    #
    # The canonical channel registry (kept in code so it's auditable):
    KNOWN_CHANNELS = {
        # Phase A: registries + awesome lists
        "mcp-so", "pulsemcp", "mcp-get",
        "awesome-mcp-mcp",        # modelcontextprotocol/servers (official MCP list)
        "awesome-mcp-punkpeye",   # punkpeye/awesome-mcp-servers
        "awesome-mcp-appcypher",  # appcypher/awesome-mcp-servers
        # Phase B reserved (framework adapters)
        "langchain", "crewai", "llamaindex", "autogen", "pydantic-ai", "letta", "langgraph",
        # Phase C reserved (community channels)
        "moltbook", "agentops", "mcp-discord", "owasp-agentic", "reddit", "hn",
        # Phase D reserved (authority weave)
        "substack", "linkedin", "twitter",
        # Bookkeeping
        "smithery",   # smithery.ai listing back-click
        "github",     # github repo back-click
        "direct",     # no via -- direct URL
    }

    def _ua_family(ua: str) -> str:
        """Coarse UA family for aggregation. NOT a fingerprint -- we only want one of
        a handful of buckets: browser, mcp-client, scanner, curl, other."""
        if not ua:
            return "unknown"
        u = ua.lower()
        if "smithery" in u or "smitherybot" in u: return "smithery-scan"
        if "mcp" in u and "browser" not in u:     return "mcp-client"
        if "curl" in u or "wget" in u or "python-requests" in u: return "curl-like"
        if "bot" in u or "crawler" in u or "spider" in u:        return "bot"
        if "mozilla" in u or "chrome" in u or "safari" in u or "firefox" in u: return "browser"
        return "other"

    async def telemetry(request):
        via_raw = (request.query_params.get("via") or "direct").strip().lower()
        # NEVER trust user input as a channel name; bucket unknowns
        via = via_raw if via_raw in KNOWN_CHANNELS else "unknown"
        kind = (request.query_params.get("kind") or "page").strip().lower()
        if kind not in ("page", "api", "card", "follow"):
            kind = "page"
        ua_family = _ua_family(request.headers.get("user-agent", ""))
        # One structured line to stderr -- Render captures + we can grep/aggregate
        print(f"[telemetry] via={via} kind={kind} ua={ua_family}", file=sys.stderr)
        return JSONResponse({"ok": True, "via": via, "kind": kind, "ua_family": ua_family})

    # Friendly landing page for humans who paste the bare URL into a browser.
    # Anyone hitting the / route is NOT an MCP client (those POST to /mcp). Serving
    # a small DDU-themed HTML page is more useful than a 404 from Starlette.
    LANDING_HTML = """<!doctype html>
<meta charset="utf-8"><title>Trust Gate MCP</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--o:#FF4500;--c:#EFEBE2;--b:#0A0A0A;--m:JetBrains Mono,monospace}
*{box-sizing:border-box;margin:0}
body{background:var(--b);color:var(--c);font-family:DM Sans,system-ui,sans-serif;line-height:1.55;padding:48px 24px;max-width:760px;margin:0 auto}
h1{font-family:Archivo Black,sans-serif;font-size:clamp(32px,5vw,52px);line-height:1.04;margin-bottom:14px}
h1 span{color:var(--o)}
p{font-size:16px;color:#cfcbc2;margin-bottom:18px}
hr{border:0;border-top:1px solid #26261f;margin:28px 0}
.kick{font-family:var(--m);font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--o);margin-bottom:18px}
ul{list-style:none;padding:0}
li{padding:14px 0;border-bottom:1px solid #26261f;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
li:last-child{border:0}
li b{font-family:var(--m);font-size:12px;color:var(--o);letter-spacing:.1em}
a{color:var(--c);text-decoration:none;border-bottom:1px solid var(--o);font-family:var(--m);font-size:13px;word-break:break-all}
a:hover{color:var(--o)}
.tag{display:inline-block;font-family:var(--m);font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--o);padding:3px 10px;border:1px solid var(--o);margin-right:6px;margin-bottom:6px}
footer{margin-top:36px;font-family:var(--m);font-size:11px;color:#8b877e}
</style>
<div class="kick">Cyber Warrior Network</div>
<h1>Trust Gate <span>MCP.</span></h1>
<script>
// Channel-attribution ping. Fires once on landing.
// ?via=<channel> -> /x?via=<channel>&kind=page. NEVER sends any PII.
(function(){
  try {
    var m = (location.search.match(/[?&]via=([^&]+)/) || [null, "direct"]);
    var via = decodeURIComponent(m[1]).toLowerCase();
    fetch("/x?via=" + encodeURIComponent(via) + "&kind=page",
          {method:"GET", credentials:"omit", cache:"no-store"})
      .catch(function(){});  // fire-and-forget; never block render
  } catch(e) {}
})();
</script>
<p>Post-quantum, tamper-evident receipts for consequential agent actions. Four tools, one shared signing primitive (Ed25519 + ML-DSA-65 + SLH-DSA via OpenAgentOntology). Verifiable offline from the certificate alone.</p>
<p><span class="tag">No receipt</span><span class="tag">No trust</span></p>
<hr>
<ul>
<li><b>MCP endpoint</b><a href="/mcp">/mcp</a></li>
<li><b>Server card</b><a href="/.well-known/mcp/server-card.json">/.well-known/mcp/server-card.json</a></li>
<li><b>Smithery</b><a href="https://smithery.ai/servers/apps/cwn-trust-gate">smithery.ai/servers/apps/cwn-trust-gate</a></li>
<li><b>Source</b><a href="https://github.com/CWNApps/trust-gate-mcp">github.com/CWNApps/trust-gate-mcp</a></li>
<li><b>OAO primitive</b><a href="https://github.com/CWNApps/openagentontology">github.com/CWNApps/openagentontology</a></li>
</ul>
<footer>Apache-2.0. Hardened to CWN pol.must_do.150 (Quantum Hardening + Codex Delivery Completeness).</footer>
"""

    async def landing(_request):
        return HTMLResponse(LANDING_HTML)

    # Friendly browser explainer for human-clicked /mcp URLs.
    # Every Moltbook /agents post, every AgentOps comment, every Discord drop, every
    # PyPI README links to https://trust-gate-mcp.onrender.com/mcp?via=<channel> as
    # a verify endpoint. Humans (not MCP clients) will click those links and -- per
    # MCP spec -- get a JSON-RPC 406 ("Not Acceptable: Client must accept
    # text/event-stream") which looks like a crash. This middleware catches the
    # browser case (GET /mcp with Accept: text/html and NOT Accept: text/event-stream)
    # and serves a DDU-themed page explaining what an MCP endpoint is + a copy-paste
    # curl example, so curious humans land somewhere useful instead of scary.
    # Real MCP clients (Smithery scan, Claude Desktop, any /mcp POST) are untouched.
    MCP_EXPLAINER_HTML = """<!doctype html>
<meta charset="utf-8"><title>Trust Gate MCP endpoint</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--o:#FF4500;--c:#EFEBE2;--b:#0A0A0A;--p:#1a1a18;--ln:#26261f;--m:JetBrains Mono,monospace}
*{box-sizing:border-box;margin:0}
body{background:var(--b);color:var(--c);font-family:DM Sans,system-ui,sans-serif;line-height:1.55;padding:48px 24px;max-width:820px;margin:0 auto}
h1{font-family:Archivo Black,sans-serif;font-size:clamp(30px,4.6vw,46px);line-height:1.04;margin-bottom:14px}
h1 span{color:var(--o)}
h2{font-family:Archivo Black,sans-serif;font-size:20px;margin:28px 0 10px}
p{font-size:16px;color:#cfcbc2;margin-bottom:14px}
.kick{font-family:var(--m);font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--o);margin-bottom:18px}
pre{background:var(--p);border:1px solid var(--ln);padding:14px 16px;font-family:var(--m);font-size:12.5px;color:var(--c);line-height:1.6;overflow-x:auto;white-space:pre;margin:8px 0 18px}
pre .o{color:var(--o)}
a{color:var(--c);text-decoration:none;border-bottom:1px solid var(--o);font-family:var(--m);font-size:13.5px}
a:hover{color:var(--o)}
.tag{display:inline-block;font-family:var(--m);font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--o);padding:3px 10px;border:1px solid var(--o);margin:0 6px 6px 0}
.btn{display:inline-block;margin-top:10px;padding:10px 18px;border:1px solid var(--o);font-family:var(--m);font-size:13px;letter-spacing:.05em;color:var(--o)}
.btn:hover{background:var(--o);color:var(--b)}
footer{margin-top:36px;font-family:var(--m);font-size:11px;color:#8b877e}
</style>
<div class="kick">Cyber Warrior Network &middot; Trust Gate</div>
<h1>This is an <span>MCP endpoint</span>, not a webpage.</h1>
<p><span class="tag">Endpoint OK</span><span class="tag">Server healthy</span> If you got here from a Moltbook, AgentOps, or Discord link, you are in the right place &mdash; just the wrong format. MCP endpoints speak JSON-RPC over HTTP and require a specific <code>Accept</code> header. Your browser sent <code>text/html</code>; the server politely declined, exactly as the spec mandates.</p>

<h2>Verify a Trust Gate receipt yourself (60 seconds, no install)</h2>
<pre>curl -X POST <span class="o">https://trust-gate-mcp.onrender.com/mcp</span> \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json, text/event-stream" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'</pre>

<h2>Or mint a calling-card receipt</h2>
<pre>curl -X POST <span class="o">https://trust-gate-mcp.onrender.com/mcp</span> \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json, text/event-stream" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"mint_action_receipt","arguments":{
         "agent_id":"anyone","operation":"hello","target":"world"}}}'</pre>

<h2>Or use the framework adapter</h2>
<pre>pip install cwn-langchain-trust-gate
<span class="o"># or cwn-crewai-trust-gate / cwn-llama-index-trust-gate</span>

from langchain_trust_gate import MintActionReceiptTool
tool = MintActionReceiptTool()
receipt = tool.invoke({
    "agent_id": "ops-bot",
    "operation": "approve_vendor_payment",
    "target": "invoice-47000",
})
print(receipt["atom_id"])</pre>

<p><a class="btn" href="/">&larr; Back to the landing page</a></p>

<footer>Apache-2.0. Source: github.com/CWNApps/trust-gate-mcp. OAO primitive: github.com/CWNApps/openagentontology.</footer>
"""

    class MCPBrowserExplainerMiddleware:
        """Catch human browser GETs on /mcp before the MCP transport 406s them.

        Real MCP clients (Claude Desktop, Smithery scan, any JSON-RPC POST) send
        `Accept: application/json, text/event-stream` or `Accept: text/event-stream`.
        Browsers send `Accept: text/html, ...`. If we see a GET /mcp with text/html
        and NOT text/event-stream, it is a human who clicked a verify-link from a
        published post -- serve them the DDU explainer instead of the JSON-RPC 406.

        Why a middleware and not a Route: a Route("/mcp", ...) would intercept ALL
        GET /mcp, including legitimate SSE-stream opens from real MCP clients
        (MCP uses GET to open server-initiated streams). The Accept-header check
        is the only honest discriminator.
        """
        def __init__(self, app, html=MCP_EXPLAINER_HTML):
            self.app = app
            # Pre-encode once. immutable. avoids a per-request encode.
            self.body = html.encode("utf-8")

        async def __call__(self, scope, receive, send):
            if (scope.get("type") == "http"
                    and scope.get("method") == "GET"
                    and scope.get("path") == "/mcp"):
                accept_b = b""
                for k, v in scope.get("headers", ()):
                    if k == b"accept":
                        accept_b = v
                        break
                accept = accept_b.decode("latin-1", "replace").lower()
                # Only treat as a browser if it explicitly asks for HTML AND does
                # NOT also accept text/event-stream (the SSE leg an MCP client
                # uses). This is the narrow human-clicker case.
                if "text/html" in accept and "text/event-stream" not in accept:
                    await send({
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"text/html; charset=utf-8"),
                            # no-store so a content fix (e.g. wrong curl example) rolls
                            # out instantly; Render edge will not serve stale HTML.
                            (b"cache-control", b"no-store"),
                            # MIME sniff protection on a static HTML response.
                            (b"x-content-type-options", b"nosniff"),
                        ],
                    })
                    await send({"type": "http.response.body", "body": self.body})
                    return
            await self.app(scope, receive, send)

    # CORS posture follows the bearer-auth toggle:
    #   bearer off  -> allow_origins=['*'] (verify-as-public-good adoption path)
    #   bearer on   -> allow_origins from TRUST_GATE_ALLOWED_ORIGINS (no '*' with credentials)
    allowed = _allowed_origins()
    auth_on = auth_active()
    print(f"[server_http] bearer_auth={'ON' if auth_on else 'OFF'} "
          f"cors_origins={allowed}", file=sys.stderr)

    # FastMCP's streamable_http_app() already exposes the MCP transport at /mcp -- so we
    # mount it at "/" (not "/mcp") to avoid double-prefixing it to /mcp/mcp. Smithery's
    # scanner POSTs to https://server/mcp and the JSON-RPC request gets handled.
    # The /.well-known/mcp/server-card.json Route is listed first so it takes priority
    # over the catch-all Mount.
    app = Starlette(
        routes=[
            Route("/", landing, methods=["GET"]),
            Route("/x", telemetry, methods=["GET"]),
            Route("/.well-known/mcp/server-card.json", server_card, methods=["GET"]),
            Mount("/", app=inner_mcp_app),
        ],
        lifespan=inner_mcp_app.router.lifespan_context,
        middleware=[
            # Outermost: short-circuit human browser GETs on /mcp before any other
            # middleware spends cycles on them. A real MCP client (Accept includes
            # text/event-stream, or POST request) passes straight through to CORS.
            # Putting this first means a human navigating to /mcp does NOT consume
            # a token from the per-IP rate-limit bucket -- a 100% non-MCP visit
            # should not count against an MCP client sharing the same IP.
            Middleware(MCPBrowserExplainerMiddleware),
            # CORS so preflight passes before any auth check sees it.
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
    # proxy_headers + forwarded_allow_ips=* are needed behind Render's TLS proxy.
    # Without them uvicorn rejects requests with "Invalid Host header" / 421
    # because it doesn't trust X-Forwarded-Host from the upstream Cloudflare/Render layer.
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info",
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
