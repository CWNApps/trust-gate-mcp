"""rate_limit.py -- minimal in-memory token-bucket starlette middleware.

A signing-oracle that anyone can hit unbounded is a free abuse vector, so any public listing
needs SOME per-IP cap before the URL is published. This 30-line bucket gives us that without
adding a runtime dep.

Caveats (documented, not workarounds):
  * Per-pod. If the deploy scales horizontally, an attacker hitting N replicas gets N x the
    budget. Honest answer: behind Smithery's gateway this is fine for v1; if usage warrants,
    move the limiter to the gateway or to a shared Redis bucket.
  * Identifies clients by the first IP in X-Forwarded-For, falling back to the connection peer.
    Spoofable upstream of a trusted gateway; honest behind one.

Default budgets (per IP):
  - mint_*    60/min  (signing oracle; cheap CPU but unbounded mint = unbounded receipt spam)
  - verify_*  600/min (read-only; bound only to stop a thrash attack)
  - default   120/min (everything else)

Override at runtime via env: RATE_LIMIT_MINT_PER_MIN, RATE_LIMIT_VERIFY_PER_MIN, RATE_LIMIT_DEFAULT_PER_MIN.

DoS hardening:
  * MAX_BUCKETS_PER_CLASS caps the per-IP bucket dict so an attacker rotating IPs cannot
    grow our memory unboundedly. Oldest entries are evicted (FIFO via dict insertion order).
  * MAX_BODY_BYTES caps the body we read for classification. A larger body is read but the
    classification is deferred to the default bucket, avoiding a memory amplification path.
"""
from __future__ import annotations

import os
import time
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP, per-route-class token-bucket limiter.

    Classifies by the JSON-RPC tool name in the request body when possible (so mint and verify
    have separate budgets). When the body isn't a tool-call (handshake, list_tools, etc.), it
    uses the default budget. Unparseable bodies fail-open to the default budget; they don't
    block the protocol's handshake messages."""

    MINT_KEYWORDS = ("mint_", "mint:")
    VERIFY_KEYWORDS = ("verify_", "verify:")
    # Caps to close the two memory-DoS amplification paths codex flagged:
    MAX_BUCKETS_PER_CLASS = 4096   # ~64KB / class; FIFO-evict the oldest IP once full
    MAX_BODY_BYTES = 64 * 1024     # read at most 64 KiB to classify; bigger -> default bucket

    def __init__(self, app) -> None:
        super().__init__(app)
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
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",", 1)[0].strip()
        return request.client.host if request.client else "unknown"

    def _bucket_for(self, body_text: str):
        # Heuristic, fast: look for the tool name in the body. The MCP body is JSON-RPC --
        # any keyword we'd block on will appear as `"name":"mint_..."` or similar. We don't
        # parse JSON because a malformed body should still be classified, not 500'd here.
        lowered = body_text.lower()
        if any(k in lowered for k in self.MINT_KEYWORDS):
            return self._mint_buckets, self.mint_cap
        if any(k in lowered for k in self.VERIFY_KEYWORDS):
            return self._verify_buckets, self.verify_cap
        return self._default_buckets, self.default_cap

    async def dispatch(self, request: Request,
                       call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        ip = self._ip(request)
        body_bytes = b""
        oversized = False
        # Only read the body for POST-like calls; GET/HEAD/handshake should not touch it.
        if request.method in ("POST", "PUT", "PATCH"):
            full_body = await request.body()
            if len(full_body) > self.MAX_BODY_BYTES:
                # Don't parse what could be a memory-amplification payload. Classify as
                # default + still forward the full body so the downstream handler can
                # reject/accept it on its own merits.
                oversized = True
                body_bytes = b""
            else:
                body_bytes = full_body

            # Restore the body for downstream handlers (we already consumed it).
            async def _receive():
                return {"type": "http.request", "body": full_body, "more_body": False}
            request._receive = _receive  # type: ignore[attr-defined]

        if oversized:
            buckets, cap = self._default_buckets, self.default_cap
        else:
            buckets, cap = self._bucket_for(
                body_bytes.decode("utf-8", errors="replace") if body_bytes else "")
        b = self._get_or_create(buckets, ip, cap)
        if not b.take():
            return JSONResponse(
                {"error": "rate_limited",
                 "message": f"Per-IP cap ({cap}/min) reached for this tool class. "
                            "Per-pod limiter -- back off and retry."},
                status_code=429,
                headers={"Retry-After": "60"})
        return await call_next(request)
