"""
pqsign_crypto.py — ML-DSA-65 signing and hybrid signature bundles.

Algorithm: ML-DSA-65 (CRYSTALS-Dilithium3, NIST FIPS 204, Security Level 3).
Deps: pqcrypto, stdlib only.

Signature types:
  mldsa65  — ML-DSA-65 detached signature
  pgp      — OpenPGP clearsign (Ed25519 or RSA; not quantum-safe)
  hybrid   — JSON bundle containing both a PGP clearsign and an ML-DSA-65
             signature over the same message; both must verify

Hybrid bundle format:
  -----BEGIN DEADMAN HYBRID SIGNATURE-----
  {
    "v": 1,
    "message": "...",
    "pgp_clearsign": "-----BEGIN PGP SIGNED MESSAGE-----\\n...",
    "mldsa65_sig": "<base64>",
    "mldsa65_pub": "<base64>"
  }
  -----END DEADMAN HYBRID SIGNATURE-----
"""

import base64
import json

from pqcrypto.sign.ml_dsa_65 import (
    generate_keypair as _gen_raw,
    sign            as _sign_raw,
    verify          as _verify_raw,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    SIGNATURE_SIZE,
)

# ── Armor markers ─────────────────────────────────────────────────────────────

_PUB_H  = "-----BEGIN MLDSA65 PUBLIC KEY-----"
_PUB_F  = "-----END MLDSA65 PUBLIC KEY-----"
_SEC_H  = "-----BEGIN MLDSA65 PRIVATE KEY-----"
_SEC_F  = "-----END MLDSA65 PRIVATE KEY-----"
_SIG_H  = "-----BEGIN MLDSA65 SIGNATURE-----"
_SIG_F  = "-----END MLDSA65 SIGNATURE-----"
_HYB_H  = "-----BEGIN DEADMAN HYBRID SIGNATURE-----"
_HYB_F  = "-----END DEADMAN HYBRID SIGNATURE-----"


def _armor(header: str, footer: str, data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    return f"{header}\n{wrapped}\n{footer}"


def _dearmor(text: str, header: str, footer: str) -> bytes:
    lines, inside, acc = text.strip().splitlines(), False, []
    for ln in lines:
        if ln.strip() == header:
            inside = True
            continue
        if ln.strip() == footer:
            break
        if inside:
            acc.append(ln.strip())
    if not acc:
        raise ValueError(f"Block not found: {header}")
    return base64.b64decode("".join(acc))


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """Generate an ML-DSA-65 keypair.
    Returns (armored_public_key, armored_private_key).
    """
    pub, priv = _gen_raw()
    return (
        _armor(_PUB_H, _PUB_F, bytes(pub)),
        _armor(_SEC_H, _SEC_F, bytes(priv)),
    )


# ── Sign ──────────────────────────────────────────────────────────────────────

def sign_message(armored_priv: str, message: str) -> str:
    """Sign a UTF-8 message with an ML-DSA-65 private key.
    Returns an armored signature block.
    """
    priv = _dearmor(armored_priv, _SEC_H, _SEC_F)
    sig  = bytes(_sign_raw(priv, message.encode("utf-8")))
    return _armor(_SIG_H, _SIG_F, sig)


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_message(armored_pub: str, message: str, armored_sig: str) -> None:
    """Verify an ML-DSA-65 signature.
    Raises ValueError on failure. Returns None on success.
    """
    pub = _dearmor(armored_pub, _PUB_H, _PUB_F)
    sig = _dearmor(armored_sig, _SIG_H, _SIG_F)
    ok = _verify_raw(pub, message.encode("utf-8"), sig)
    if not ok:
        raise ValueError("Signature invalid.")


# ── Hybrid bundle (PGP + ML-DSA-65) ──────────────────────────────────────────

def make_hybrid_bundle(
    pgp_clearsign: str,
    armored_mldsa_sig: str,
    armored_mldsa_pub: str,
    message: str,
) -> str:
    """Combine a PGP clearsign and an ML-DSA-65 signature into a hybrid bundle.
    Both signatures must cover the same message.
    """
    payload = json.dumps({
        "v": 1,
        "message":      message,
        "pgp_clearsign": pgp_clearsign,
        "mldsa65_sig":  base64.b64encode(
                            _dearmor(armored_mldsa_sig, _SIG_H, _SIG_F)
                        ).decode(),
        "mldsa65_pub":  base64.b64encode(
                            _dearmor(armored_mldsa_pub, _PUB_H, _PUB_F)
                        ).decode(),
    }, indent=2)
    return f"{_HYB_H}\n{payload}\n{_HYB_F}"


def parse_hybrid_bundle(bundle: str) -> dict:
    """Parse a Deadman hybrid signature bundle.
    Returns dict with keys: message, pgp_clearsign, mldsa65_sig (bytes), mldsa65_pub (bytes).
    """
    lines, inside, acc = bundle.strip().splitlines(), False, []
    for ln in lines:
        if ln.strip() == _HYB_H:
            inside = True
            continue
        if ln.strip() == _HYB_F:
            break
        if inside:
            acc.append(ln)
    if not acc:
        raise ValueError("No hybrid bundle block found")
    data = json.loads("\n".join(acc))
    if data.get("v") != 1:
        raise ValueError(f"Unknown hybrid bundle version: {data.get('v')}")
    return {
        "message":       data["message"],
        "pgp_clearsign": data["pgp_clearsign"],
        "mldsa65_sig":   base64.b64decode(data["mldsa65_sig"]),
        "mldsa65_pub":   base64.b64decode(data["mldsa65_pub"]),
    }


def verify_hybrid_bundle(bundle_text: str, gpg) -> dict:
    """Verify a hybrid bundle. Both PGP and ML-DSA-65 signatures must be valid.
    gpg: gnupg.GPG instance.
    Raises on failure. Returns dict with pgp_info, mldsa_info, message on success.
    """
    b = parse_hybrid_bundle(bundle_text)

    # 1. Verify PGP clearsign
    pgp_result = gpg.verify(b["pgp_clearsign"])
    if not pgp_result.valid:
        raise ValueError(
            f"PGP signature invalid — status: {pgp_result.status}, "
            f"key_id: {pgp_result.key_id or '(unknown)'}"
        )

    # 2. Verify ML-DSA-65
    pub_armored = _armor(_PUB_H, _PUB_F, b["mldsa65_pub"])
    sig_armored = _armor(_SIG_H, _SIG_F, b["mldsa65_sig"])
    verify_message(pub_armored, b["message"], sig_armored)  # raises on failure

    return {
        "pgp_info":   {"key_id": pgp_result.key_id, "username": pgp_result.username,
                       "status": pgp_result.status},
        "mldsa_info": {"pub_size": len(b["mldsa65_pub"]), "algorithm": "ML-DSA-65 (FIPS 204)"},
        "message":    b["message"],
    }


# ── Key sizes (for display) ───────────────────────────────────────────────────
KEY_INFO = {
    "algorithm":  "ML-DSA-65 (CRYSTALS-Dilithium3)",
    "standard":   "NIST FIPS 204, Security Level 3",
    "pub_bytes":  PUBLIC_KEY_SIZE,
    "priv_bytes": SECRET_KEY_SIZE,
    "sig_bytes":  SIGNATURE_SIZE,
}
