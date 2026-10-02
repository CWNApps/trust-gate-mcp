# Trust Gate MCP -- Smithery container-runtime image.
# Speaks MCP Streamable HTTP at /mcp on $PORT (Smithery sets PORT=8081).
FROM python:3.12-slim

WORKDIR /app

RUN python -m pip install --no-cache-dir --upgrade pip

# Runtime deps, from PyPI with version bounds. The post-quantum legs come from openagentontology[pq];
# by default that is dilithium-py, a pure-Python library its authors say is not for cryptographic use
# (see README). Add liboqs-python to this image for a native backend (it may build liboqs from source
# the first time it is imported).
RUN pip install --no-cache-dir \
        "mcp>=1.12,<2" \
        "openagentontology[pq]>=0.2,<0.3" \
        "uvicorn>=0.30" \
        "starlette>=0.37"

COPY src/trust_gate_mcp/server.py src/trust_gate_mcp/server_http.py src/trust_gate_mcp/bootstrap.py src/trust_gate_mcp/rate_limit.py src/trust_gate_mcp/auth.py /app/

# Persistent state directory for the signing keys AND key_metadata.json. Mount a volume here at
# deploy time -- without it the key changes on every container restart: receipts signed earlier still
# verify from their own certificate, but a pinned kid stops matching new ones.
ENV OAO_RECEIPT_KEY=/data/oao/receipt_ed25519.pem
ENV OAO_REQUIRE_PQ=true
RUN mkdir -p /data/oao
VOLUME ["/data/oao"]

# Bootstrap key + metadata on every boot (idempotent). FAIL-CLOSED on kid drift.
# Then start the HTTP MCP server.
CMD ["sh", "-c", "python /app/bootstrap.py && python /app/server_http.py"]

EXPOSE 8081
