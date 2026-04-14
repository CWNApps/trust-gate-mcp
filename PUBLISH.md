# Publishing `trust-gate-mcp`

This document takes you from the current local repo to a live, listed MCP server on 3 registries.

**Prerequisites**:
- GitHub CLI authenticated: `gh auth login`
- PyPI account (for step 4): https://pypi.org/account/register
- Smithery account: https://smithery.ai
- Glama account: https://glama.ai

All commands below assume cwd = `C:\Users\nigel\cwn-trust-gate-mcp`.

---

## Step 1 — Create GitHub Repo + Push

```bash
cd C:\Users\nigel\cwn-trust-gate-mcp

# Authenticate (one-time)
gh auth login

# Create the repo under cyber-warrior-network org (public)
gh repo create cyber-warrior-network/trust-gate-mcp \
  --public \
  --description "Policy-gated AI decisions with Ed25519 cryptographic receipts. No receipt, no trust." \
  --homepage "https://cwn-trust-gate.onrender.com" \
  --source=. \
  --remote=origin \
  --push

# Verify
gh repo view cyber-warrior-network/trust-gate-mcp --web
```

If the `cyber-warrior-network` org doesn't exist yet, create it at https://github.com/organizations/new (free for public repos).

### Alternative: Push to personal account

If you don't have the org set up yet, push to your personal account as a placeholder:

```bash
gh repo create trust-gate-mcp \
  --public \
  --description "Policy-gated AI decisions with Ed25519 cryptographic receipts. No receipt, no trust." \
  --homepage "https://cwn-trust-gate.onrender.com" \
  --source=. \
  --remote=origin \
  --push
```

Then transfer to the org later: `gh repo transfer trust-gate-mcp cyber-warrior-network`.

---

## Step 2 — Tag v0.1.0 Release

```bash
git tag -a v0.1.0 -m "v0.1.0 - Initial release"
git push origin v0.1.0

gh release create v0.1.0 \
  --title "Trust Gate MCP v0.1.0" \
  --notes-file CHANGELOG.md \
  --verify-tag
```

---

## Step 3 — Register on Smithery

Smithery auto-discovers GitHub repos with a `smithery.yaml` at root.

**Option A (auto)**: Go to https://smithery.ai/new and paste the repo URL.
Smithery will parse `smithery.yaml` and auto-list.

**Option B (manual)**:
1. Sign in at https://smithery.ai
2. Click **New Server**
3. Repository URL: `https://github.com/cyber-warrior-network/trust-gate-mcp`
4. Entry point: `trust-gate-mcp` (from `pyproject.toml` scripts)
5. Config: Smithery will pre-fill from `smithery.yaml`
6. Publish

**Verify**: https://smithery.ai/server/@cyber-warrior-network/trust-gate-mcp

---

## Step 4 — Register on Glama

Glama uses `glama.json` at the repo root.

1. Sign in at https://glama.ai
2. Click **Submit MCP Server**
3. Repository URL: `https://github.com/cyber-warrior-network/trust-gate-mcp`
4. Glama will parse `glama.json` automatically
5. Submit for review

**Verify**: https://glama.ai/mcp/servers/trust-gate-mcp

---

## Step 5 — Register on MCPMarket

MCPMarket.com is a curated directory.

1. Go to https://mcpmarket.com/submit
2. Paste repo URL: `https://github.com/cyber-warrior-network/trust-gate-mcp`
3. Use `mcpmarket.md` in this repo as the submission copy (title, tagline, description)
4. Category: `Security`, `AI Safety`, `Compliance`
5. Submit for review

**Also add to**:
- https://github.com/modelcontextprotocol/servers (official MCP server list — open PR)
- https://mcpservers.org/submit (community directory)
- https://pulsemcp.com/add (aggregator)

---

## Step 6 — Publish to PyPI (enables `uvx trust-gate-mcp` and `pip install`)

```bash
# Install build tool (one-time)
pip install build twine

# Build wheels
python -m build

# Upload to PyPI (will prompt for API token)
twine upload dist/*

# Verify
pip install trust-gate-mcp
uvx trust-gate-mcp --help
```

Get a PyPI API token at https://pypi.org/manage/account/token/ — create one scoped to `trust-gate-mcp` after the first upload.

---

## Step 7 — Submit PR to Official MCP Servers List

The canonical registry is https://github.com/modelcontextprotocol/servers.

```bash
gh repo fork modelcontextprotocol/servers --clone --remote
cd servers
```

Edit `README.md` under the **Community Servers** section, add alphabetically:

```markdown
- **[Trust Gate](https://github.com/cyber-warrior-network/trust-gate-mcp)** - Policy-gated AI decisions with Ed25519 cryptographic receipts. Every decision produces a signed TrustAtom receipt — mathematical proof the action was evaluated, authorized, and recorded.
```

Open PR:

```bash
git checkout -b add-trust-gate-mcp
git add README.md
git commit -m "Add Trust Gate MCP server"
git push -u origin add-trust-gate-mcp
gh pr create --title "Add Trust Gate MCP server" --body "Adds Trust Gate - policy-gated AI decisions with Ed25519 cryptographic receipts. Apache-2.0."
```

---

## Verification Checklist

After all steps complete, verify each lookup works:

- [ ] `gh repo view cyber-warrior-network/trust-gate-mcp` shows the repo
- [ ] Repo is public and browsable on github.com
- [ ] `v0.1.0` tag + GitHub release exists
- [ ] `pip install trust-gate-mcp` works (after PyPI publish)
- [ ] `uvx trust-gate-mcp` starts the MCP server (stdio waits on stdin)
- [ ] Smithery listing shows the 4 tools + config schema
- [ ] Glama listing shows the 4 tools + metadata
- [ ] MCPMarket listing accepted (email confirmation)
- [ ] PR to `modelcontextprotocol/servers` opened

---

## After Publishing — GTM Steps

1. **Announcement post** — LinkedIn, X, Substack (use copy from `mcpmarket.md`)
2. **Docs link** — add "Install via MCP" section to https://cwn-trust-gate.onrender.com
3. **Slack #general** — post link to the Smithery listing
4. **HN/Reddit** — post to `r/LocalLLaMA`, `r/ClaudeAI`, `r/mcp`
5. **Usage metrics** — wire Glama/Smithery download counts into the Trust Gate dashboard

---

_Last updated: 2026-04-14 — FFLART Run 10 P0-1b_
