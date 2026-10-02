"""rate_limit.py -- minimal in-memory token-bucket starlette middleware.

A signing-oracle that anyone can hit unbounded is a free abuse vector, so any public listing
needs SOME per-IP cap before the URL is published. This small bucket gives us that without
adding a runtime dep.

Caveats (documented, not workarounds):
  * Per-pod. If the deploy scales horizontally, an attacker hitting N replicas gets N x the
    budget; put the limit at a gateway or in a shared store if you run more than one.
  * Signing runs on the event loop (about 70 ms per call with the default backend), so the per-IP
    budget bounds one client but there is no overall cap on signing work.
  * Identifies clients by request.client, which uvicorn fills from X-Forwarded-For only for the
    proxies named in TRUST_GATE_FORWARDED_ALLOW_IPS (default: any, which is spoofable; set it to your
    proxy's address when you have one). A request is refused with 413 as soon as its body exceeds
    MAX_REQUEST_BYTES (at most that much is buffered).

Default budgets (per IP):
  - signing tools (mint_*, gate_decision, check_egress, run_exit_drill)  60/min  (a signing oracle;
    unbounded signing = unbounded receipt spam)
  - verify_*  600/min (read-only; bound only to stop a thrash attack)
  - default   120/min (everything else)

Override at runtime via env: RATE_LIMIT_MINT_PER_MIN, RATE_LIMIT_VERIFY_PER_MIN, RATE_LIMIT_DEFAULT_PER_MIN.

DoS hardening:
  * MAX_BUCKETS_PER_CLASS caps the per-IP bucket dict so an attacker rotating IPs cannot
    grow our memory unboundedly. Oldest entries are evicted (FIFO via dict insertion order).
  * MAX_BODY_BYTES caps the body we PARSE for classification; a body over it, or one that cannot be
    parsed, is charged to the signing bucket, so padding or re-encoding a call buys no extra
    budget. MAX_REQUEST_BYTES caps what is buffered at all (413 above it).
  * Verification also runs on the event loop (about 20 ms), so the verify budget bounds one client
    but is not an overall cap either.
"""
from __future__ import annotations

import json

import os
import time

from starlette.requests import Request
from starlette.responses import JSONResponse


def _budget(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


class TokenBucket:
    """Single-IP token bucket. Tokens refill at rate (capacity / window_seconds) per second."""
    __slots__ = ("capacity", "rate", "tokens", "last")

    def __init__(self, capacity: int, window_seconds: float = 60.0) -> None:
        self.capacity = float(capacity)
        self.rate = float(capacity) / window_seconds
        self.tokens = float(capacity)
        self.last = time.monotonic()

    def take(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimitMiddleware:
    """Per-IP, per-route-class token-bucket limiter, written as plain ASGI middleware so that the body it
    buffers is replayed to the application (a BaseHTTPMiddleware would hand the endpoint an empty one).

    Classifies by the JSON-RPC tool name in the request body when possible (so mint and verify
    have separate budgets). When the body isn't a tool-call (handshake, list_tools, etc.), it
    uses the default budget. A body that cannot be parsed is charged to the signing bucket."""

    # Tools that SIGN. gate_decision, check_egress and run_exit_drill sign as well as the mint_ tools
    # do, so they share the mint budget. Classification uses the parsed JSON-RPC tool name.
    SIGNING_TOOLS = frozenset({"mint_receipt_for_record_change", "mint_action_receipt",
                               "gate_decision", "check_egress", "run_exit_drill"})
    VERIFY_TOOLS = frozenset({"verify_receipt"})
    # Caps to close the two memory-DoS amplification paths found in testing:
    MAX_BUCKETS_PER_CLASS = 4096   # ~64KB / class; FIFO-evict the oldest IP once full
    MAX_BODY_BYTES = 64 * 1024     # parse at most 64 KiB to classify; bigger -> the SIGNING bucket
    MAX_REQUEST_BYTES = 1024 * 1024  # refuse anything larger with 413 before it is buffered

    def __init__(self, app) -> None:
        self.app = app
        self._mint_buckets: dict[str, TokenBucket] = {}
        self._verify_buckets: dict[str, TokenBucket] = {}
        self._default_buckets: dict[str, TokenBucket] = {}
        self.mint_cap = _budget("RATE_LIMIT_MINT_PER_MIN", 60)
        self.verify_cap = _budget("RATE_LIMIT_VERIFY_PER_MIN", 600)
        self.default_cap = _budget("RATE_LIMIT_DEFAULT_PER_MIN", 120)

    def _get_or_create(self, buckets: dict, ip: str, cap: int) -> TokenBucket:
        """Bounded bucket store with FIFO eviction. Prevents an IP-rotation attack from
        growing the per-class dict without limit."""
        b = buckets.get(ip)
        if b is not None:
            return b
        if len(buckets) >= self.MAX_BUCKETS_PER_CLASS:
            # Evict the oldest entry. Python dicts preserve insertion order, so popitem(last=False)
            # via next(iter(...)) gives FIFO. Cheap and bounded.
            try:
                oldest = next(iter(buckets))
                del buckets[oldest]
            except StopIteration:
                pass
        b = TokenBucket(capacity=cap, window_seconds=60.0)
        buckets[ip] = b
        return b

    def _ip(self, request: Request) -> str:
        # The server (uvicorn) resolves X-Forwarded-For according to FORWARDED_ALLOW_IPS /
        # TRUST_GATE_FORWARDED_ALLOW_IPS before this middleware runs, so request.client is the one
        # place the client identity comes from. Reading the header here as well would let any client
        # choose its own identity even when no proxy is trusted.
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _tool_names(body):
        """Tool names called by a JSON-RPC body (single call or batch), or None if the body cannot be
        parsed. The body is parsed as the application parses it, from the raw bytes (so a byte-order
        mark, UTF-16 and UTF-32 are read exactly as the transport reads them). Parsing decodes
        escapes, so "m\\u0069nt_action_receipt" is seen as what it is, and a tool name can no longer be
        dodged by hiding a word in the arguments."""
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):   # includes UnicodeDecodeError
            return None
        items = data if isinstance(data, list) else [data]
        names = set()
        for item in items:
            if isinstance(item, dict) and item.get("method") == "tools/call":
                params = item.get("params")
                if isinstance(params, dict) and isinstance(params.get("name"), str):
                    names.add(params["name"])
        return names

    def _bucket_for(self, body):
        """The bucket store and cap for a request body (bytes or text). A body that cannot be parsed is
        charged to the signing bucket: it cannot be classified, and the strict budget is the safe one."""
        if not body:
            return self._default_buckets, self.default_cap
        names = self._tool_names(body)
        if names is None:
            return self._mint_buckets, self.mint_cap
        if names & self.SIGNING_TOOLS:
            return self._mint_buckets, self.mint_cap
        if names & self.VERIFY_TOOLS:
            return self._verify_buckets, self.verify_cap
        return self._default_buckets, self.default_cap

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        ip = self._ip(request)
        body_bytes = b""
        oversized = False
        replay = receive
        # Only read the body for POST-like calls; GET/HEAD/handshake should not touch it.
        if scope["method"] in ("POST", "PUT", "PATCH"):
            chunks, total = [], 0
            while True:                      # stops reading at the cap, with or without a Content-Length
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > self.MAX_REQUEST_BYTES:
                    await JSONResponse({"error": "request_too_large"}, status_code=413)(scope, receive, send)
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            full_body = b"".join(chunks)
            if len(full_body) > self.MAX_BODY_BYTES:
                # Don't parse what could be a memory-amplification payload. Padding a call past
                # the cap must not buy a bigger budget, so classify it into the stricter signing
                # bucket, and still forward the full body so the downstream handler can
                # reject/accept it on its own merits.
                oversized = True
                body_bytes = b""
            else:
                body_bytes = full_body
            delivered = False

            async def replay():
                """The buffered body once, then whatever the server sends next (a disconnect)."""
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": full_body, "more_body": False}
                return await receive()

        if oversized:
            buckets, cap = self._mint_buckets, self.mint_cap
        else:
            buckets, cap = self._bucket_for(body_bytes)
        b = self._get_or_create(buckets, ip, cap)
        if not b.take():
            await JSONResponse(
                {"error": "rate_limited",
                 "message": f"Per-IP cap ({cap}/min) reached for this tool class. "
                            "Per-pod limiter -- back off and retry."},
                status_code=429,
                headers={"Retry-After": "60"})(scope, receive, send)
            return
        await self.app(scope, replay, send)
