"""test_release_consistency.py -- the numbers and claims a release publishes must agree with the code.

Why this file exists: in 0.2.1 the static server card said "version 0.2.0, four tools" while the
code had seven, the audit tool's description promised a signed receipt it never minted, and the
docs called SLH-DSA a default leg although it needs liboqs. Each is a sentence a buyer's
security team can quote back. These checks fail the build when the text drifts from the code.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile

import pytest

from trust_gate_mcp import __version__, server as srv

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _pyproject_version():
    m = re.search(r'^version\s*=\s*"([^"]+)"', _text("pyproject.toml"), re.M)
    assert m, "no version in pyproject.toml"
    return m.group(1)


def test_every_place_that_states_the_version_agrees():
    v = srv.SERVER_VERSION
    assert __version__ == v
    assert _pyproject_version() == v
    assert json.loads(_text("server.json"))["version"] == v
    assert json.loads(_text("glama.json"))["version"] == v
    assert f"## {v} " in _text("CHANGELOG.md")


def test_the_registry_entry_states_the_real_tool_count():
    pytest.importorskip("mcp")
    n = len(srv.describe_tools(srv.build_server()))
    meta = json.loads(_text("server.json"))["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
    assert meta["build_info"]["tools_count"] == n


def test_the_server_card_is_built_from_the_running_server():
    pytest.importorskip("mcp")
    server = srv.build_server()
    card = srv.build_server_card(server)
    assert card["version"] == srv.SERVER_VERSION
    assert [t["name"] for t in card["tools"]] == [t["name"] for t in srv.describe_tools(server)]
    assert len(card["tools"]) == 7
    assert all(t["description"] for t in card["tools"])
    assert f"{len(card['tools'])} tools" in card["description"]
    assert "gate_decision" in {t["name"] for t in card["tools"]}


SHIPPED_TEXT = ("pyproject.toml", ".github/workflows/publish-pypi.yml", ".github/workflows/publish-ghcr.yml", ".github/workflows/tests.yml",
                "src/trust_gate_mcp/__init__.py", "src/trust_gate_mcp/server.py", "src/trust_gate_mcp/server_http.py",
                "src/trust_gate_mcp/bootstrap.py", "src/trust_gate_mcp/rate_limit.py", "src/trust_gate_mcp/auth.py",
                "README.md", "glama.json", "mcpmarket.md", "server.json", "smithery.yaml", "Dockerfile")

STALE = [
    (r"\bfour tools\b", "tool count that is out of date (there are seven)"),
    (r"\b0\.2\.0\b", "a version string from the old server card"),
    (r"with a signed receipt", "audit_my_agent_inventory mints no receipt"),
    (r"ML-DSA-65 \+ SLH-DSA", "SLH-DSA is only present when liboqs is installed, so it is not a default leg"),
    (r"33/33", "test count that is out of date"),
    (r"execution permit", "the old description of a permit that was granted for everything"),
    (r"no server to trust", "verification proves integrity only, not who signed"),
    (r"who does not trust you", "verification proves integrity only, not who signed"),
    (r"EU AI Act Article 50", "a compliance claim the product does not support"),
    (r"\(FIPS 205\)|fips-205", "the hash-based leg is the pre-standard SPHINCS+ variant, not byte-compatible with FIPS 205"),
    (r"lattice break", "the hash-based key is not bound to the kid, so this reads as more than it delivers"),
    (r"for a quantum tomorrow", "the default ML-DSA backend is unhardened"),
    (r"wherever they appear", "the sensitive-word lists are finite"),
    (r"defeats signature.stripping|defends against.{0,40}downgrade", "PQ-required checks presence, not whose key"),
    (r"never stored in the clear", "unsalted hashes of low-entropy values are guessable and the gate records action and resource in clear"),
    (r"[Bb]locks RESTRICTED", "check_egress flags; it cannot block anything"),
    (r"PUBLIC / INTERNAL|PUBLIC/INTERNAL", "the all-clear label was renamed NO_MARKERS_FOUND"),
    (r"plus a hash-based leg|hash-based leg (?:when|with) (?:the installed )?liboqs|hash-based third leg",
     "the primitive looks for one SPHINCS+ variant, which liboqs 0.16 removed, so the extra adds no third leg today"),
    (r"SLH-DSA|slh-dsa", "the optional leg is pre-standard SPHINCS+ and is only there if liboqs ships it"),
    (r"post-quantum receipt", "the kid covers Ed25519 only, so a receipt is hybrid-signed, not post-quantum as a whole"),
    (r"sha256\(verify_pubkey_b64\)", "the kid hashes the canonical re-encoding of the key"),
    (r"same notary", "a kid is copyable; only a verified Ed25519 signature ties it to a signer"),
    (r"kid equality", "comparing kids does not show who signed"),
    (r"no side effects", "the drill signs a receipt, which creates the signing key on a fresh host"),
    (r"support SLAs?", "no support commitment is made by this package"),
    (r"every push", "tests.yml runs on pushes to main and on pull requests"),
]


@pytest.mark.parametrize("rel", SHIPPED_TEXT)
def test_shipped_text_contains_no_known_stale_or_overclaiming_phrase(rel):
    text = _text(rel)
    hits = [(pat, why) for pat, why in STALE if re.search(pat, text, re.I)]
    # README's upgrade note names the affected versions on purpose
    if rel == "README.md":
        hits = [(p, w) for p, w in hits if p != r"\b0\.2\.0\b"]
    assert not hits, f"{rel}: {hits}"


def test_the_changelog_names_the_versions_that_had_the_defect_and_states_what_is_not_covered():
    text = _text("CHANGELOG.md")
    head = " ".join(text.split("## 0.2.1", 1)[0].split())  # collapse line wraps
    assert "0.2.1" in head and "GRANTED" in head
    assert "does not change" in head.lower()
    assert "never released" in head.lower()

# ---- nothing internal ships in the public tree ------------------------------------------------
# The public repo must not carry workstation paths or personal addresses. These patterns are generic.
_GENERIC_PATTERNS = [
    r"\b[A-Za-z]:[\\/]",                                           # a drive-letter path
    r"/(?:Users|home)/[^/\s]+/",                                     # a home-directory path
    r"@(?:gmail|outlook|hotmail|yahoo|icloud|proton)\.",            # a personal address
]


def _forbidden_hits(text):
    """Number of generic patterns found in text."""
    return sum(1 for pat in _GENERIC_PATTERNS if re.search(pat, text, re.I | re.M))


def _tracked_files():
    """The files git tracks, or None when this is not a git checkout (an extracted sdist)."""
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    return [ROOT / line for line in out.stdout.splitlines() if line]


def _public_text_files():
    skip_dirs = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv"}
    tracked = _tracked_files()
    paths = tracked if tracked is not None else sorted(ROOT.rglob("*"))
    for path in paths:
        if not path.is_file() or any(part in skip_dirs or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix in (".pyc", ".png", ".ico"):
            continue
        yield path.relative_to(ROOT).as_posix(), path


def test_the_public_tree_scan_actually_reads_the_files_it_is_meant_to_check():
    names = {rel for rel, _ in _public_text_files()}
    assert {"README.md", "CHANGELOG.md", "src/trust_gate_mcp/server.py", "src/trust_gate_mcp/server_http.py",
            ".github/workflows/publish-pypi.yml", "smithery.yaml", "tests/test_release_consistency.py"} <= names


def test_the_guard_fires_on_planted_examples_and_stays_quiet_on_ordinary_text():
    assert _forbidden_hits("ordinary release notes about receipts and gates") == 0
    assert _forbidden_hits("docs for /srv/example are only a fake path in a test") == 0
    for text in ("see C" + ":" + chr(92) + "Users" + chr(92) + "someone", "see D" + ":/data/x", "in /ho" + "me/someone/notes",
                 "see /Us" + "ers/someone/notes", "mail me at someone@gm" + "ail.com"):
        assert _forbidden_hits(text) >= 1, text


def test_no_internal_reference_ships_in_the_public_tree():
    hits = []
    for rel, path in _public_text_files():
        n = _forbidden_hits(path.read_text(encoding="utf-8", errors="replace")) + _forbidden_hits(rel)
        if n:
            hits.append((rel, n))
    assert not hits, hits


# ---- the sdist ships the package and nothing else ---------------------------------------------
SDIST_ROOT_FILES = {"CHANGELOG.md", "LICENSE", "README.md", "pyproject.toml", "PKG-INFO", ".gitignore"}


def test_the_sdist_contains_only_the_package_and_its_readme(tmp_path):
    """Hatchling's default sdist is every tracked file; 0.2.1 shipped maintainer notes, a publishing
    script and a demo page to PyPI that way. Build the real sdist and check its file list."""
    pytest.importorskip("hatchling")
    proc = subprocess.run([sys.executable, "-m", "hatchling", "build", "-t", "sdist", "-d", str(tmp_path)],
                          cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-800:]
    archives = list(tmp_path.glob("*.tar.gz"))
    assert len(archives) == 1, archives
    with tarfile.open(archives[0]) as tar:
        names = [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile()]
    assert "src/trust_gate_mcp/server.py" in names, names  # the archive really holds the package
    stray = [n for n in names if n not in SDIST_ROOT_FILES and not n.startswith("src/trust_gate_mcp/")]
    assert not stray, stray
