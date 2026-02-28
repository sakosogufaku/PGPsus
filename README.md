# PGPsus 🔐

**Alpha release** — A terminal TUI for PGP, Age, and post-quantum hybrid encryption.

Built with [Textual](https://github.com/Textualize/textual). No Electron, no browser, no nonsense.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)

---

## Features

- **PGP encrypt / decrypt** — full GPG keyring integration, multi-recipient support
- **Age encryption** — modern XChaCha20-Poly1305 via [age](https://age-encryption.org)
- **PQC hybrid** — post-quantum + classical hybrid encryption
- **Sign & verify** — GPG signing and signature verification
- **File operations** — encrypt/decrypt files directly
- **Key management** — import, export, search, and browse your keyring
- **Keyserver lookup** — search and fetch keys by email or fingerprint
- **4 themes** — Dark, Light, ☁️ Heavenly, 🔥 Infernal
- **Clipboard** — Ctrl+C copy, Ctrl+V paste (works in Whonix / Xfce Terminal)
- **Tor-friendly** — designed for use on Whonix and Tails

---

## Install

```bash
git clone https://github.com/sakosogufaku/PGPsus.git
cd PGPsus
bash setup.sh
./PGPsus
```

Requires: `python3`, `gpg`. The setup script handles everything else in a local venv (no sudo needed).

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `textual` | TUI framework |
| `python-gnupg` | GPG keyring integration |
| `pqcrypto` | Post-quantum primitives |
| `cryptography` | Age / modern crypto |

---

## Usage

| Key | Action |
|-----|--------|
| `Ctrl+E` | Encrypt tab |
| `Ctrl+D` | Decrypt tab |
| `Ctrl+S` | Sign/Verify tab |
| `Ctrl+K` | Keys tab |
| `Ctrl+F` | File tab |
| `Ctrl+V` / `F2` | Paste from clipboard |
| `Ctrl+C` / `F3` | Copy to clipboard |
| `Ctrl+Q` | Quit |

---

## Privacy notes

- No telemetry, no network calls (except optional keyserver lookup)
- All encryption is local — nothing leaves your machine
- Designed for use on [Whonix](https://www.whonix.org) and [Tails](https://tails.boum.org)

---

## Status

**Alpha** — core functionality works. Expect rough edges. Issues and PRs welcome.

---

## License

MIT
