# Trust Gate MCP -- Smithery container-runtime image.
# Speaks MCP Streamable HTTP at /mcp on $PORT (Smithery sets PORT=8081).
FROM python:3.12-slim

WORKDIR /app

RUN python -m pip install --no-cache-dir --upgrade pip

# Pin the runtime deps. The post-quantum legs come from openagentontology[pq].
RUN pip install --no-cache-dir \
        "mcp>=1.12,<2" \
        "openagentontology[pq] @ git+https://github.com/CWNApps/openagentontology.git@main" \
        "uvicorn>=0.30" \
        "starlette>=0.37"

COPY src/trust_gate_mcp/server.py src/trust_gate_mcp/server_http.py src/trust_gate_mcp/bootstrap.py src/trust_gate_mcp/rate_limit.py src/trust_gate_mcp/auth.py /app/

# Persistent state directory for the Ed25519 + ML-DSA-65 + SLH-DSA signing keys
# AND key_metadata.json. Mount a volume here at deploy time -- without it the key
# rotates every container restart and breaks every receipt's verification chain.
ENV OAO_RECEIPT_KEY=/data/oao/receipt_ed25519.pem
ENV OAO_REQUIRE_PQ=true
RUN mkdir -p /data/oao
VOLUME ["/data/oao"]

# Bootstrap key + metadata on every boot (idempotent). FAIL-CLOSED on kid drift.
# Then start the HTTP MCP server.
CMD ["sh", "-c", "python /app/bootstrap.py && python /app/server_http.py"]

EXPOSE 8081
