"""bootstrap.py -- ensure the persistent signing-key state exists before the server boots.

Three responsibilities, all idempotent:

  1. Force first-run key generation so the Ed25519 + ML-DSA-65 + SLH-DSA keys land at
     $OAO_RECEIPT_KEY (the in-container path mapped to the persistent volume).
  2. Write key_metadata.json next to the keys: { kid, created_at, algorithms, oao_version }
     so an operator can audit "is this still the same notary as last week?" without parsing
     the PEM file.
  3. Refuse to overwrite an existing metadata file (so a rotation is a deliberate act, not
     a side-effect of a restart). If the on-disk metadata's kid mismatches the live key on
     boot, we log loudly and ABORT -- a silent mismatch would break every receipt chain.

The "kid" is the truncated SHA-256 of the Ed25519 public key bytes. It is deterministic --
the same key always gives the same kid -- so a verifier comparing two receipts can answer
"signed by the same notary?" by checking kid equality, without trusting any registry.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path


def _kid_for_pubkey_b64(pub_b64: str) -> str:
    """kid = first 32 hex chars of sha256(verify_pubkey_b64). 128 bits of identifier --
    adversarial collision resistance well past the lifetime of any one notary key.
    MUST match server.py _kid(); both helpers are tested against this exact algorithm."""
    return hashlib.sha256(pub_b64.encode("ascii")).hexdigest()[:32]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def ensure_keys_and_metadata(*, key_path: str | None = None,
                             write_metadata: bool = True) -> dict:
    """Idempotent key + metadata bootstrap. Returns the metadata dict actually on disk."""
    # Locate the receipt module the same way server.py does -- works both as an installed
    # package and as a repo checkout under oss/openagentontology/.
    try:
        from openagentontology import receipt as oao_receipt
    except ImportError:
        here = Path(__file__).resolve()
        dev = here.parents[5]
        sys.path.insert(0, str(dev / "oss" / "openagentontology"))
        from openagentontology import receipt as oao_receipt

    key_path = key_path or os.environ.get("OAO_RECEIPT_KEY") or str(
        Path.home() / ".openagentontology" / "receipt_ed25519.pem")
    key_file = Path(key_path)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    # Mint a one-off no-op receipt with a deterministic, empty body. This forces _load_key
    # to generate + persist the Ed25519 PEM if it does not exist; the PQ sidecars land
    # alongside it via the same key_base. Cheap (a few ms) and idempotent.
    probe = oao_receipt.mint_receipt({"source": "bootstrap_probe", "nodes": [], "edges": [],
                                       "action_maps": [], "frameworks": []},
                                      decision="BOOTSTRAP_PROBE", key_path=key_path)
    pub_b64 = probe.get("verify_pubkey_b64", "")
    algs = []
    if probe.get("signature_b64"):           algs.append("Ed25519")
    if probe.get("ml_dsa_signature_b64"):    algs.append("ML-DSA-65")
    if probe.get("slh_dsa_signature_b64"):   algs.append("SLH-DSA")
    kid = _kid_for_pubkey_b64(pub_b64) if pub_b64 else ""

    meta_file = key_file.with_name("key_metadata.json")
    if meta_file.exists():
        # Existing metadata: FAIL-CLOSED on three branches -- unreadable, missing-kid, or
        # kid-mismatch. Any of these means we cannot prove "still the same notary as last
        # boot," so we must not silently accept new traffic that would forge that claim.
        try:
            on_disk = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[bootstrap] FATAL: key_metadata.json present but unreadable ({exc}). "
                  "Cannot prove notary continuity. ABORT.", file=sys.stderr)
            raise SystemExit(78)
        if not on_disk.get("kid"):
            print("[bootstrap] FATAL: key_metadata.json missing 'kid' field. "
                  "Cannot prove notary continuity. ABORT.", file=sys.stderr)
            raise SystemExit(78)
        if not kid:
            print("[bootstrap] FATAL: could not derive live key kid (no public key from probe). "
                  "ABORT.", file=sys.stderr)
            raise SystemExit(78)
        if on_disk["kid"] != kid:
            print(f"[bootstrap] FATAL: live key kid={kid} does NOT match on-disk metadata "
                  f"kid={on_disk['kid']}. The signing key was replaced silently. ABORT.",
                  file=sys.stderr)
            raise SystemExit(78)  # EX_CONFIG -- "the operator must intervene"
        return on_disk

    metadata = {
        "kid": kid,
        "created_at": _now_iso(),
        "algorithms": algs,
        "oao_version": getattr(oao_receipt, "__version__", "unknown"),
        "note": "kid is sha256(verify_pubkey_b64)[:32] (128 bits); a verifier comparing "
                "receipts can answer 'signed by the same notary?' by checking kid equality "
                "offline, without trusting any registry.",
    }
    if write_metadata:
        meta_file.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def main() -> None:
    meta = ensure_keys_and_metadata()
    # stderr, not stdout -- stdout is the JSON-RPC channel under stdio transport.
    print(f"[bootstrap] kid={meta.get('kid')} algs={meta.get('algorithms')}", file=sys.stderr)


if __name__ == "__main__":
    main()
