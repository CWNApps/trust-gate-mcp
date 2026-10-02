"""bootstrap.py -- ensure the persistent signing-key state exists before the server boots.

Three responsibilities, all idempotent:

  1. Force first-run key generation so the Ed25519 and post-quantum signing keys land at
     $OAO_RECEIPT_KEY (the in-container path mapped to the persistent volume).
  2. Write key_metadata.json next to the keys: { kid, created_at, algorithms, oao_version }
     so an operator can see whether the Ed25519 key is the same as last week's without
     parsing the PEM file.
  3. Refuse to overwrite an existing metadata file (so a rotation is a deliberate act, not
     a side-effect of a restart). If the on-disk metadata's kid mismatches the live key on
     boot, we log loudly and ABORT -- a silent mismatch would break every receipt chain.

The "kid" is the truncated SHA-256 of the canonical base64 of the Ed25519 public key. It is deterministic --
the same key always gives the same kid -- so it names a key. It does not prove who used the key: it is
copyable, so a verifier must not trust a kid merely because a receipt prints it. To check who signed
a receipt, pass the kid you trust out of band as `expected_kid` to verify_receipt, or compare the kid
that verify_receipt reports (which is set only when that key's own Ed25519 signature verified).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path


def _kid_for_pubkey_b64(pub_b64: str) -> str:
    """kid = first 32 hex chars of sha256 over the canonical base64 of the 32 key bytes: 128 bits, which
    is ample for the second-preimage resistance a pin relies on (it is not 128-bit collision
    resistance). The same algorithm as server.py _kid(); a test pins them together."""
    import base64
    import binascii
    try:
        raw = base64.b64decode(pub_b64, validate=True)
    except (ValueError, binascii.Error):
        return ""
    if len(raw) != 32:
        return ""
    return hashlib.sha256(base64.b64encode(raw)).hexdigest()[:32]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def ensure_keys_and_metadata(*, key_path: str | None = None,
                             write_metadata: bool = True) -> dict:
    """Idempotent key + metadata bootstrap. Returns the metadata dict actually on disk."""
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
    if probe.get("slh_dsa_signature_b64"):   algs.append("hash-based")
    kid = _kid_for_pubkey_b64(pub_b64) if pub_b64 else ""

    meta_file = key_file.with_name("key_metadata.json")
    if meta_file.exists():
        # Existing metadata: FAIL-CLOSED on three branches -- unreadable, missing-kid, or
        # kid-mismatch. Any of these means we cannot show it is still the same Ed25519 key as
        # last boot, so we must not silently accept new traffic that would forge that claim.
        try:
            on_disk = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[bootstrap] FATAL: key_metadata.json present but unreadable ({exc}). "
                  "Cannot show key continuity. ABORT.", file=sys.stderr)
            raise SystemExit(78)
        if not on_disk.get("kid"):
            print("[bootstrap] FATAL: key_metadata.json missing 'kid' field. "
                  "Cannot show key continuity. ABORT.", file=sys.stderr)
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
        "note": "kid is the first 32 hex characters of the sha256 of the canonical base64 of the Ed25519 "
                "public key. It names a key and is copyable: to check who signed a receipt, pass this "
                "value as expected_kid to verify_receipt.",
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
