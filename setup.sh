#!/usr/bin/env bash
# setup.sh — one-time setup for PGPsus
# Creates a local venv and installs all dependencies.
# Safe to re-run; wipes and rebuilds venv if something is broken.
#
# Strategy (no sudo required):
#   1. Try: uv venv  (uv handles missing ensurepip/python3-venv)
#   2. Try: python3 -m venv  (works if python3-venv installed)
#   3. Try: python3 -m venv --system-site-packages  (Debian fallback)
#   4. Fail with clear instructions

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/venv"
REQ="$DIR/requirements.txt"

echo "[PGPsus] Setting up..."

# ── 1. Require python3 ────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install it first (apt install python3)." >&2
    exit 1
fi

# ── 2. Ensure uv is available (no sudo; falls back to --break-system-packages) ─
ensure_uv() {
    command -v uv &>/dev/null && return 0
    # Try pip install uv (user scope first, then break-system as last resort)
    if python3 -m pip install --user uv -q 2>/dev/null; then
        export PATH="$HOME/.local/bin:$PATH"
        command -v uv &>/dev/null && return 0
    fi
    if python3 -m pip install --user uv --break-system-packages -q 2>/dev/null; then
        export PATH="$HOME/.local/bin:$PATH"
        command -v uv &>/dev/null && return 0
    fi
    return 1
}

# ── 3. Create venv ─────────────────────────────────────────────────────────────
if [ ! -d "$VENV" ] || [ ! -f "$VENV/bin/python" ]; then
    rm -rf "$VENV"
    echo "[PGPsus] Creating venv..."

    if ensure_uv; then
        uv venv "$VENV" --quiet && echo "[PGPsus] Venv created via uv."
    elif python3 -m venv "$VENV" 2>/dev/null; then
        echo "[PGPsus] Venv created."
    elif python3 -m venv --system-site-packages "$VENV" 2>/dev/null; then
        echo "[PGPsus] Venv created (system site-packages)."
    else
        echo "ERROR: Cannot create venv." >&2
        echo "  Option A (no sudo): pip3 install uv --break-system-packages && uv venv $VENV" >&2
        echo "  Option B:           sudo apt install python3-venv" >&2
        exit 1
    fi
fi

PYTHON="$VENV/bin/python"

# ── 4. Install / sync dependencies ────────────────────────────────────────────
echo "[PGPsus] Installing dependencies..."
if command -v uv &>/dev/null; then
    uv pip install -r "$REQ" --python "$PYTHON" -q
elif [ -f "$VENV/bin/pip" ]; then
    "$VENV/bin/pip" install --upgrade pip -q
    "$VENV/bin/pip" install -r "$REQ" -q
else
    # No pip in venv — bootstrap it
    curl -sSL https://bootstrap.pypa.io/get-pip.py | "$PYTHON" - -q
    "$VENV/bin/pip" install -r "$REQ" -q
fi

# ── 5. Verify ──────────────────────────────────────────────────────────────────
if "$PYTHON" -c "import textual, gnupg, pqcrypto, cryptography" 2>/dev/null; then
    "$PYTHON" -c "
import textual, cryptography
print('[PGPsus] All dependencies OK.')
print('  textual:      ', textual.__version__)
print('  cryptography: ', cryptography.__version__)
"
else
    echo "[PGPsus] ERROR: Dependency check failed after install." >&2
    echo "  Try: $PYTHON -m pip install -r $REQ" >&2
    exit 1
fi

echo "[PGPsus] Setup complete. Run: ./PGPsus"
