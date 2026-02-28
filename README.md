# PGPsus v1.2

Terminal TUI for PGP and post-quantum cryptography. Requires Python 3.10+.

## Features

- PGP encrypt, decrypt, sign, verify (GPG keyring integration)
- ML-DSA-65 post-quantum signing (NIST FIPS 204)
- PQC hybrid encryption (X25519 + ML-KEM-768)
- PGP + ML-DSA-65 hybrid signing key generation
- Symmetric encryption (AES-256, Camellia-256, Twofish)
- File encrypt/decrypt (GPG and PQC)
- Batch decrypt (mixed PGP/PQC blocks)
- Keyserver lookup and key import/export
- Clipboard support: Ctrl+V paste, Ctrl+Y copy
- UTC clock in UI

## Install

```bash
unzip PGPsus_v1.2.zip -d PGPsus
cd PGPsus
bash setup.sh
./PGPsus
```

Requires `gpg` in PATH.

## Key types

| Type | Use |
|------|-----|
| Ed25519 | PGP signing and encryption |
| RSA 4096 / 2048 | PGP (legacy compatibility) |
| PQC Encrypt (X25519+ML-KEM-768) | Asymmetric encryption only |
| PGP + ML-DSA-65 (hybrid signing) | Dual-algorithm signing bundle |

## Signing challenge format (for Deadman Storage)

```
DEADMAN-OTP: <64-hex-nonce>
```

Sign with PQC Sign tab -> ML-DSA-65 Sign mode.
