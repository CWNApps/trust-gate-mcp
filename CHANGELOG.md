# Changelog

All notable changes to `trust-gate-mcp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-14

### Added
- Initial public release.
- Four MCP tools: `gate_decision`, `verify_receipt`, `check_policy`, `health`.
- Stdio transport via `FastMCP`.
- Async HTTP client with configurable base URL, API key, tenant, timeout.
- Ed25519 receipt verification (mathematical, zero server-trust).
- Bearer token authentication for Trust Gate API.
- Full pytest coverage (21 tests).
- Apache-2.0 license.

### Integrations
- Claude Desktop (stdio via `uvx` or `pip install`).
- Claude Code (`claude mcp add trust-gate -- uvx trust-gate-mcp`).
- Any MCP-compatible client (Cursor, Zed, Windsurf, Cline, etc.).

### Action Types Supported
- `READ_EVIDENCE`, `GRAPH_READ` — low-risk, no receipt required
- `CODE_GENERATION` — medium-risk
- `GRAPH_WRITE`, `EXPORT_INTEGRATION`, `DEPLOY` — receipt required
- `MODIFY_POLICY` — receipt + human approval required

### Trust Gate Platform
- Backed by [cwn-trust-gate.onrender.com](https://cwn-trust-gate.onrender.com)
- Ed25519 signing on cryptographic boundary
- OPA policy evaluation
- Neo4j immutable decision graph
- TrustAtom receipt protocol

[0.1.0]: https://github.com/cyber-warrior-network/trust-gate-mcp/releases/tag/v0.1.0
