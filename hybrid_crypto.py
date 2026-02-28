"""
hybrid_crypto.py — X25519 + ML-KEM-768 hybrid encryption (FIPS 203)

Format (armored):
  -----BEGIN HYBRID MESSAGE-----
  base64(version[1] || x25519_ephem_pub[32] || mlkem_ct[1088] || nonce[12] || aes_ct[...])
  -----END HYBRID MESSAGE-----

Key format (armored JSON):
  -----BEGIN HYBRID PUBLIC KEY-----  /  -----BEGIN HYBRID PRIVATE KEY-----

Security properties:
  - Requires BOTH X25519 and ML-KEM-768 to be broken to compromise message.
  - AES-256-GCM authenticated encryption over combined KDF(X25519_ss || MLKEM_ss).
  - Ephemeral sender key per message — no long-term sender state needed.
"""

import base64
import json
import os
import struct
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as mlkem_gen,
    encrypt as mlkem_enc,
    decrypt as mlkem_dec,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    CIPHERTEXT_SIZE,
)

VERSION = b'\x01'
ARMOR_PUB  = ("-----BEGIN HYBRID PUBLIC KEY-----",  "-----END HYBRID PUBLIC KEY-----")
ARMOR_PRIV = ("-----BEGIN HYBRID PRIVATE KEY-----", "-----END HYBRID PRIVATE KEY-----")
ARMOR_MSG  = ("-----BEGIN HYBRID MESSAGE-----",     "-----END HYBRID MESSAGE-----")


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair() -> tuple[dict, dict]:
    """Returns (public_key_dict, private_key_dict)."""
    x_priv = X25519PrivateKey.generate()
    x_pub  = x_priv.public_key()
    ml_pub_bytes, ml_priv_bytes = mlkem_gen()

    pub = {
        "v": 1,
        "x25519":   base64.b64encode(x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        "mlkem768": base64.b64encode(bytes(ml_pub_bytes)).decode(),
    }
    priv = {
        "v": 1,
        "x25519":   base64.b64encode(x_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
        "mlkem768": base64.b64encode(bytes(ml_priv_bytes)).decode(),
    }
    return pub, priv


def armor_public_key(pub: dict) -> str:
    data = base64.b64encode(json.dumps(pub).encode()).decode()
    return f"{ARMOR_PUB[0]}\n{data}\n{ARMOR_PUB[1]}"


def armor_private_key(priv: dict) -> str:
    data = base64.b64encode(json.dumps(priv).encode()).decode()
    return f"{ARMOR_PRIV[0]}\n{data}\n{ARMOR_PRIV[1]}"


def parse_public_key(armored: str) -> dict:
    return _parse_armor(armored, ARMOR_PUB)


def parse_private_key(armored: str) -> dict:
    return _parse_armor(armored, ARMOR_PRIV)


def _parse_armor(text: str, markers: tuple) -> dict:
    lines = text.strip().splitlines()
    body_lines = []
    inside = False
    for line in lines:
        if line.strip() == markers[0]:
            inside = True; continue
        if line.strip() == markers[1]:
            break
        if inside:
            body_lines.append(line.strip())
    raw = base64.b64decode("".join(body_lines))
    return json.loads(raw)


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt(plaintext: str | bytes, pub: dict) -> str:
    """Encrypt plaintext to armored hybrid message."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()

    # 1. Ephemeral X25519
    ephem_priv = X25519PrivateKey.generate()
    ephem_pub  = ephem_priv.public_key()
    x_recip    = X25519PublicKey.from_public_bytes(base64.b64decode(pub["x25519"]))
    x_ss       = ephem_priv.exchange(x_recip)  # 32 bytes

    # 2. ML-KEM-768 encapsulation
    ml_pub_bytes = base64.b64decode(pub["mlkem768"])
    ml_ct, ml_ss = mlkem_enc(ml_pub_bytes)      # ml_ss = 32 bytes

    # 3. Combine secrets via HKDF-SHA256
    combined_key = HKDF(
        algorithm=SHA256(), length=32, salt=None,
        info=b"hybrid-pgq-v1"
    ).derive(x_ss + bytes(ml_ss))

    # 4. AES-256-GCM encrypt
    nonce = os.urandom(12)
    ct    = AESGCM(combined_key).encrypt(nonce, plaintext, None)

    # 5. Pack and armor
    ephem_pub_bytes = ephem_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    payload = VERSION + ephem_pub_bytes + bytes(ml_ct) + nonce + ct
    b64 = base64.b64encode(payload).decode()
    # Wrap at 64 chars
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    return f"{ARMOR_MSG[0]}\n{wrapped}\n{ARMOR_MSG[1]}"


# ── Decryption ────────────────────────────────────────────────────────────────

def decrypt(armored: str, priv: dict) -> str:
    """Decrypt armored hybrid message. Returns plaintext string."""
    # Parse armor
    lines = armored.strip().splitlines()
    body = []
    inside = False
    for line in lines:
        if line.strip() == ARMOR_MSG[0]:
            inside = True; continue
        if line.strip() == ARMOR_MSG[1]:
            break
        if inside:
            body.append(line.strip())
    payload = base64.b64decode("".join(body))

    # Unpack
    offset = 0
    ver = payload[offset:offset+1]; offset += 1
    if ver != VERSION:
        raise ValueError(f"Unknown version: {ver!r}")
    ephem_pub_bytes = payload[offset:offset+32]; offset += 32
    ml_ct           = payload[offset:offset+CIPHERTEXT_SIZE]; offset += CIPHERTEXT_SIZE
    nonce           = payload[offset:offset+12]; offset += 12
    ct              = payload[offset:]

    # 1. X25519 DH
    x_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv["x25519"]))
    ephem_pub = X25519PublicKey.from_public_bytes(ephem_pub_bytes)
    x_ss = x_priv.exchange(ephem_pub)

    # 2. ML-KEM decapsulation
    ml_priv_bytes = base64.b64decode(priv["mlkem768"])
    ml_ss = mlkem_dec(ml_priv_bytes, ml_ct)

    # 3. HKDF combine
    combined_key = HKDF(
        algorithm=SHA256(), length=32, salt=None,
        info=b"hybrid-pgq-v1"
    ).derive(x_ss + bytes(ml_ss))

    # 4. AES-256-GCM decrypt
    plaintext = AESGCM(combined_key).decrypt(nonce, ct, None)
    return plaintext.decode()
