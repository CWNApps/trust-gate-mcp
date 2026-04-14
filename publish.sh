#!/usr/bin/env bash
# One-shot publishing script for trust-gate-mcp
# Usage: bash publish.sh
# Prerequisites: gh authenticated (`gh auth login`), python 3.10+, pip install build twine
set -euo pipefail

REPO_SLUG="${TGM_REPO_SLUG:-cyber-warrior-network/trust-gate-mcp}"
VERSION="$(grep -oP 'version\s*=\s*"\K[^"]+' pyproject.toml | head -1)"

echo ">>> Publishing trust-gate-mcp v${VERSION} to ${REPO_SLUG}"

# Step 1 — auth check
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: gh not authenticated. Run: gh auth login" >&2
  exit 1
fi

# Step 2 — create repo + push (no-op if repo exists)
if gh repo view "${REPO_SLUG}" >/dev/null 2>&1; then
  echo ">>> Repo ${REPO_SLUG} already exists — syncing"
  git remote add origin "https://github.com/${REPO_SLUG}.git" 2>/dev/null || true
  git push -u origin main
else
  echo ">>> Creating repo ${REPO_SLUG}"
  gh repo create "${REPO_SLUG}" \
    --public \
    --description "Policy-gated AI decisions with Ed25519 cryptographic receipts. No receipt, no trust." \
    --homepage "https://cwn-trust-gate.onrender.com" \
    --source=. \
    --remote=origin \
    --push
fi

# Step 3 — tag + release
if ! git rev-parse "v${VERSION}" >/dev/null 2>&1; then
  echo ">>> Tagging v${VERSION}"
  git tag -a "v${VERSION}" -m "v${VERSION}"
  git push origin "v${VERSION}"
fi

if ! gh release view "v${VERSION}" --repo "${REPO_SLUG}" >/dev/null 2>&1; then
  echo ">>> Creating GitHub release v${VERSION}"
  gh release create "v${VERSION}" \
    --repo "${REPO_SLUG}" \
    --title "Trust Gate MCP v${VERSION}" \
    --notes-file CHANGELOG.md \
    --verify-tag
fi

echo ""
echo ">>> GitHub publish complete."
echo ">>> Repo: https://github.com/${REPO_SLUG}"
echo ""
echo "NEXT (manual):"
echo "  - PyPI:       python -m build && twine upload dist/*"
echo "  - Smithery:   https://smithery.ai/new  (paste repo URL)"
echo "  - Glama:      https://glama.ai/mcp/submit  (paste repo URL)"
echo "  - MCPMarket:  https://mcpmarket.com/submit"
echo "  - Official list PR: see PUBLISH.md Step 7"
