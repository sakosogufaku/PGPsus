#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 captaincanary contributors
"""PGPsus v1.7 - PGP / PQC signing and encryption TUI."""
VERSION = "1.8"

import gnupg, os, re, base64, json, subprocess, shutil
import time as _time
import threading
import datetime
import urllib.request
import socket, struct, hashlib, secrets
from urllib.parse import quote as url_quote
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes
os.environ["TZ"] = "UTC"
_time.tzset()
import pqsign_crypto
from pathlib import Path
from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane,
    TextArea, Select, SelectionList, Button, Label, Input, Static
)
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive  # noqa: F401 – kept for subclass use
from textual.events import Paste
from textual import on

import hybrid_crypto


class SafeTextArea(TextArea):
    """TextArea with paste debounce — prevents double-paste from both
    bracketed-paste (on_paste) and TextArea's built-in Ctrl+V (action_paste)."""
    def on_paste(self, event: Paste) -> None:
        event.stop()
        if self.app._paste_allowed():  # type: ignore[attr-defined]
            self.insert(event.text)

    def action_paste(self) -> None:
        if self.app._paste_allowed():  # type: ignore[attr-defined]
            super().action_paste()

def _clipboard_paste() -> str:
    """Read clipboard text using whatever tool is available."""
    for cmd in (
        ["wl-paste", "--no-newline"],
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["pbpaste"],
    ):
        if shutil.which(cmd[0]):
            try:
                return subprocess.check_output(cmd, timeout=2).decode()
            except Exception:
                pass
    return ""


def _clipboard_copy(text: str) -> bool:
    """Write text to system clipboard. Returns True on success."""
    for cmd in (
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), timeout=2, check=True)
                return True
            except Exception:
                pass
    return False

# -- GPG setup -----------------------------------------------------------------
GPG_HOME = os.environ.get("GNUPGHOME", str(Path.home() / ".gnupg"))
gpg = gnupg.GPG(gnupghome=GPG_HOME)
gpg.encoding = "utf-8"

PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", re.DOTALL)
HYB_BLOCK_RE = re.compile(
    r"-----BEGIN HYBRID MESSAGE-----.*?-----END HYBRID MESSAGE-----", re.DOTALL)

# -- Deadman Storage utilities ------------------------------------------------
_DM_ONION   = "kb6lxykxqasqm4j4vses5cdkbgi7hrmez4ttllvh6g4wec3ufpju7tid.onion"
_DM_SALT    = b"deadman-v1"
_BIP39_PATH = os.path.join(os.path.dirname(__file__),
              "../opencanary-pkgs/passlib/_data/wordsets/bip39.txt")

def _dm_words():
    path = os.path.normpath(_BIP39_PATH)
    with open(path) as f:
        words = [w.strip() for w in f if w.strip()]
    assert len(words) == 2048
    return words

def _dm_entropy_to_mnemonic(entropy: bytes) -> str:
    words = _dm_words()
    h = hashlib.sha256(entropy).digest()
    ent_int = int.from_bytes(entropy, "big")
    cs_int  = int.from_bytes(h, "big") >> 248
    combined = (ent_int << 8) | cs_int
    result = []
    for _ in range(24):
        result.append(words[combined & 0x7FF])
        combined >>= 11
    return " ".join(reversed(result))

def _dm_mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = _dm_words()
    wl = mnemonic.strip().split()
    if len(wl) != 24:
        raise ValueError(f"Expected 24 words, got {len(wl)}")
    combined = 0
    for w in wl:
        combined = (combined << 11) | words.index(w)
    cs = combined & 0xFF
    entropy = (combined >> 8).to_bytes(32, "big")
    expected = int.from_bytes(hashlib.sha256(entropy).digest(), "big") >> 248
    if cs != expected:
        raise ValueError("BIP39 checksum mismatch — invalid mnemonic")
    return entropy

def _dm_hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=_hashes.SHA256(), length=32,
                salt=_DM_SALT, info=info).derive(ikm)

def _dm_derive(mnemonic: str) -> dict:
    e          = _dm_mnemonic_to_entropy(mnemonic)
    vault_id   = _dm_hkdf(e, b"vault-id")
    switch_key = _dm_hkdf(e, b"switch")
    switch_ver = _dm_hkdf(switch_key, b"switch-verifier")
    return {"vault_id": vault_id.hex(), "switch_verifier": switch_ver.hex()}

def _dm_socks5(host: str, port: int = 80, proxy: str = "127.0.0.1:9050"):
    ph, pp = proxy.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((ph, int(pp)))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise ConnectionError("SOCKS5 auth failed")
    addr = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack(">H", port))
    r = s.recv(10)
    if r[1] != 0:
        raise ConnectionError(f"SOCKS5 connect failed: {r[1]}")
    return s

def _dm_http_post(path: str, body: dict, gateway: str, proxy: str) -> dict:
    host = gateway.replace("http://", "").rstrip("/")
    data = json.dumps(body).encode()
    req  = (f"POST {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n"
            ).encode() + data
    sock = _dm_socks5(host, 80, proxy)
    sock.sendall(req)
    resp = b""
    while True:
        d = sock.recv(4096)
        if not d:
            break
        resp += d
    sock.close()
    _, _, body_raw = resp.decode().partition("\r\n\r\n")
    return json.loads(body_raw)

def gpg_pub_keys():
    return [(k["uids"][0] if k["uids"] else k["keyid"], k["fingerprint"]) for k in gpg.list_keys()]

def gpg_sec_keys():
    return [(k["uids"][0] if k["uids"] else k["keyid"], k["fingerprint"]) for k in gpg.list_keys(True)]

def xmr_latest_block() -> str:
    """Fetch latest Monero block height, hash, and timestamp via public node JSON-RPC."""
    try:
        payload = json.dumps({
            "jsonrpc": "2.0", "id": "0", "method": "get_last_block_header"
        }).encode()
        req = urllib.request.Request(
            "https://node.sethforprivacy.com/json_rpc",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
        hdr = data["result"]["block_header"]
        ts_utc = datetime.datetime.utcfromtimestamp(hdr["timestamp"]).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"Latest XMR block: #{hdr['height']}\n"
            f"Hash: {hdr['hash']}\n"
            f"Timestamp: {ts_utc}\n"
            f"Source: node.sethforprivacy.com"
        )
    except Exception as e:
        return f"XMR fetch failed: {e}"

# -- Themes --------------------------------------------------------------------
THEMES = {
    "dark": Theme(
        name="dark",
        primary="#3a8a3a", secondary="#3a3a8a",
        background="#0d0d0d", surface="#111111",
        panel="#161616", foreground="#e8e8e8",
        success="#4ec94e", warning="#c9a04e", error="#c94e4e",
        dark=True,
    ),
    "light": Theme(
        name="light",
        primary="#1a7a1a", secondary="#1a1a9a",
        background="#f5f5f0", surface="#ffffff",
        panel="#e8e8e0", foreground="#1a1a1a",
        success="#1a7a1a", warning="#8a6a00", error="#9a1a1a",
        dark=False,
    ),
    "heavenly": Theme(
        name="heavenly",
        primary="#2a8fd4", secondary="#5ab8f0",
        background="#f0f8ff", surface="#ffffff",
        panel="#e0f0fa", foreground="#1a2a3a",
        success="#2a9a5a", warning="#c07a00", error="#cc2a2a",
        dark=False,
    ),
    "infernal": Theme(
        name="infernal",
        primary="#c84a1a", secondary="#8a1a1a",
        background="#0d0500", surface="#1a0800",
        panel="#220b00", foreground="#f0c880",
        success="#c87a1a", warning="#c8a01a", error="#ff3a1a",
        dark=True,
    ),
}

SWATCHES = {
    "dark":     ["#0d0d0d","#111111","#3a8a3a","#e8e8e8","#a8e8a8"],
    "light":    ["#f5f5f0","#ffffff","#1a7a1a","#1a1a1a","#1a4a1a"],
    "heavenly": ["#f0f8ff","#ffffff","#2a8fd4","#1a2a3a","#5ab8f0"],
    "infernal": ["#0d0500","#1a0800","#c84a1a","#f0c880","#ff8040"],
}
SWATCH_LABELS = ["bg","surface","primary","text","output"]

CSS = """
Screen { background: $background; color: $foreground; }

#theme-bar {
    height: 5;
    background: #1a1a1a;
    border-bottom: solid #333333;
    padding: 0 1;
}
#theme-bar.light {
    background: #e8e8e0;
    border-bottom: solid #cccccc;
}
#theme-bar.heavenly {
    background: #ddf0fb;
    border-bottom: solid #90c8e8;
}
#theme-bar-row1 { height: 3; align: left middle; }
#theme-bar-row2 { height: 2; align: left middle; }
#theme-bar Label { color: #888888; margin-right: 1; }
#theme-bar.light Label { color: #555555; }
#theme-bar.heavenly Label { color: #2a8fd4; }
#theme-bar.infernal Label { color: #c84a1a; }
#theme-btn-dark     { width: 8; background: #444444; color: #cccccc; border: none; margin-right: 1; }
#theme-btn-light    { width: 8; background: #444444; color: #cccccc; border: none; margin-right: 1; }
#theme-btn-heavenly { width: 8; background: #444444; color: #cccccc; border: none; margin-right: 1; }
#theme-btn-infernal { width: 8; background: #444444; color: #cccccc; border: none; margin-right: 1; }
#theme-btn-dark:hover     { background: #555555; }
#theme-btn-light:hover    { background: #555555; }
#theme-btn-heavenly:hover { background: #555555; }
#theme-btn-infernal:hover { background: #555555; }
.swatch { width: 3; height: 1; margin: 0 0 0 1; }
#utc-clock { color: #888888; }
#theme-bar.light #utc-clock { color: #555555; }
#theme-bar.heavenly #utc-clock { color: #2a8fd4; }
#theme-bar.infernal #utc-clock { color: #c84a1a; }

#sidebar {
    width: 32;
    background: $surface;
    border-right: solid $border;
    padding: 1 1;
}
#sidebar Label { color: $text-muted; margin-bottom: 1; }
#sidebar Select { width: 100%; margin-bottom: 1; }
#sidebar Input  { width: 100%; margin-bottom: 1; }
#sidebar Button { width: 100%; margin-bottom: 1; }
#sidebar SelectionList { height: 8; margin-bottom: 1; }

#main-area { width: 1fr; padding: 0 1; }

TextArea {
    height: 1fr;
    border: solid $border;
    background: $surface;
    color: $foreground;
}
.output-area {
    height: 1fr;
    border: solid $success;
    background: $panel;
    color: $text;
}
.section-label { color: $text-muted; height: 1; margin: 0 0 0 1; }

#status-bar {
    height: 1;
    background: $panel;
    border-top: solid $border;
    padding: 0 1;
    color: $text-muted;
}
.status-ok  { color: $success; }
.status-err { color: $error;   }
/* Lock layout so Tabs bar never scrolls off-screen */
TabbedContent            { height: 1fr; overflow: hidden hidden; }
TabbedContent ContentSwitcher { height: 1fr; overflow: hidden hidden; }
TabPane                  { height: 1fr; overflow: hidden hidden; }
.merged-pane             { height: 1fr; overflow: hidden hidden; }
/* Sidebar and main area scroll independently */
#sidebar   { overflow-y: auto; }
#main-area { overflow-y: auto; }
.tab-section { height: auto; }
.tab-section.hidden { display: none; }
.hidden { display: none; }
/* Keys tab: fixed initial heights so Alt+Up/Down has a concrete starting point */
#keys-text        { height: 12; }
#ks-out           { height: 8;  }
#keys-import-text { height: 8;  }
#keys-import-out  { height: 4;  }
#keys-export-out  { height: 10; }
#batch-pqc-keys   { height: 4;  }
/* Compact paired action buttons (Encrypt/Clear, Run/Clear, etc.) */
.btn-row { height: 3; margin-bottom: 1; }
.btn-row Button { width: 1fr; margin-bottom: 0; }
"""

class PGPsus(App):
    CSS = CSS
    TITLE = "PGPsus"
    BINDINGS = [
        ("ctrl+q",   "quit",              "Quit"),
        ("ctrl+e",   "tab('tab-enc')",    "Encrypt"),
        ("ctrl+d",   "tab('tab-dec')",    "Decrypt"),
        ("ctrl+s",   "tab('tab-sign')",   "Sign"),
        ("ctrl+p",   "tab('tab-pqcsign')","PQC Sign"),
        ("ctrl+k",   "tab('tab-keys')",   "Keys"),
        ("ctrl+f",   "tab('tab-file')",   "File"),
        ("ctrl+m",   "tab('tab-deadman')", "Deadman"),
        ("ctrl+v",   "paste",             "Paste"),
        ("ctrl+y",   "copy",              "Copy"),
        ("alt+up",    "resize_up",      "Taller"),
        ("alt+down",  "resize_down",    "Shorter"),
        ("alt+left",  "resize_left",    "Narrower"),
        ("alt+right", "resize_right",   "Wider"),
    ]

    def _insert_text(self, text: str) -> None:
        """Insert text into the currently focused TextArea or Input."""
        w = self.focused
        if isinstance(w, TextArea) and not w.read_only:
            w.insert(text)
        elif isinstance(w, Input):
            pos = w.cursor_position
            w.value = w.value[:pos] + text + w.value[pos:]
            w.cursor_position = pos + len(text)

    def _paste_allowed(self) -> bool:
        """Return True if enough time has passed since last paste (1s debounce)."""
        now = _time.monotonic()
        if now - getattr(self, "_last_paste_time", 0) < 1.0:
            self.notify("Paste ignored (too fast — wait 1s)", severity="warning")
            return False
        self._last_paste_time = now
        return True

    def on_paste(self, event: Paste) -> None:
        """Handle terminal bracketed paste — only for Input fields (SafeTextArea handles TextArea)."""
        event.stop()
        if isinstance(self.focused, SafeTextArea):
            return  # SafeTextArea.on_paste handles this with its own debounce
        if self._paste_allowed():
            self._insert_text(event.text)

    def action_paste(self) -> None:
        """Ctrl+V: read from system clipboard and insert into focused widget."""
        if not self._paste_allowed():
            return
        text = _clipboard_paste()
        if text:
            self._insert_text(text)
        else:
            self.notify("No clipboard tool found (install xclip or wl-clipboard)", severity="warning")

    def action_copy(self) -> None:
        """Ctrl+Y: copy focused TextArea content (or selection) to clipboard."""
        w = self.focused
        text = ""
        if isinstance(w, TextArea):
            text = w.selected_text or w.text
        elif isinstance(w, Input):
            text = w.value
        if not text:
            return
        if _clipboard_copy(text):
            self.notify("Copied to clipboard.")
        else:
            self.notify("No clipboard tool found (install xclip or wl-clipboard)", severity="warning")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="theme-bar"):
            with Horizontal(id="theme-bar-row1"):
                yield Label("Theme:")
                yield Button("Dark",     id="theme-btn-dark")
                yield Button("Light",    id="theme-btn-light")
                yield Button("Heavenly", id="theme-btn-heavenly")
                yield Button("Infernal", id="theme-btn-infernal")
                for i, (color, lbl) in enumerate(zip(SWATCHES["dark"], SWATCH_LABELS)):
                    yield Static(" ", id=f"sw{i}", classes="swatch")
            with Horizontal(id="theme-bar-row2"):
                yield Label("", id="utc-clock", classes="utc-clock")
        with TabbedContent(id="tabs"):
            with TabPane("Encrypt",     id="tab-enc"):  yield self._enc_merged_pane()
            with TabPane("Decrypt",     id="tab-dec"):  yield self._dec_merged_pane()
            with TabPane("Sign/Verify", id="tab-sign"):    yield self._sign_verify_pane()
            with TabPane("PQC Sign",    id="tab-pqcsign"): yield self._pqcsign_pane()
            with TabPane("Keys",        id="tab-keys"):    yield self._keys_merged_pane()
            with TabPane("File",        id="tab-file"): yield self._file_pane()
            with TabPane("Deadman",     id="tab-deadman"): yield self._deadman_pane()
        yield Label("Ready", id="status-bar")
        yield Footer()

    def on_mount(self):
        for name, theme in THEMES.items():
            self.register_theme(theme)
        self.theme = "dark"
        self._apply_swatches("dark")
        self.set_interval(1.0, self._update_utc_clock)
        self._update_utc_clock()

    def _update_utc_clock(self):
        now = datetime.datetime.utcnow()
        self.query_one("#utc-clock", Label).update(now.strftime("%Y-%m-%d %H:%M:%S UTC"))

    # -- Theme bar -------------------------------------------------------------
    def _apply_swatches(self, theme_name: str):
        colors = SWATCHES[theme_name]
        labels = SWATCH_LABELS
        for i, (color, lbl) in enumerate(zip(colors, labels)):
            sw = self.query_one(f"#sw{i}", Static)
            sw.styles.background = color
            sw.tooltip = lbl

    _THEME_ACTIVE   = {"dark": "#3a8a3a", "light": "#3a9a3a", "heavenly": "#2a8fd4", "infernal": "#c84a1a"}
    _THEME_INACTIVE = {"dark": "#444444", "light": "#444444", "heavenly": "#444444", "infernal": "#444444"}
    _THEME_CLASSES  = {"dark": set(),     "light": {"light"},  "heavenly": {"heavenly"}, "infernal": {"infernal"}}

    def _switch_theme(self, theme_name: str):
        self.theme = theme_name
        self._apply_swatches(theme_name)
        bar = self.query_one("#theme-bar")
        bar.remove_class("light", "heavenly", "infernal")
        for cls in self._THEME_CLASSES[theme_name]:
            bar.add_class(cls)
        for t in ("dark", "light", "heavenly", "infernal"):
            btn = self.query_one(f"#theme-btn-{t}")
            if t == theme_name:
                btn.styles.background = self._THEME_ACTIVE[theme_name]
                btn.styles.color      = "#ffffff"
            else:
                btn.styles.background = self._THEME_INACTIVE[t]
                btn.styles.color      = "#888888"
        self.set_status(f"Theme: {theme_name}")

    @on(Button.Pressed, "#theme-btn-dark")
    def theme_dark(self):     self._switch_theme("dark")

    @on(Button.Pressed, "#theme-btn-light")
    def theme_light(self):    self._switch_theme("light")

    @on(Button.Pressed, "#theme-btn-heavenly")
    def theme_heavenly(self): self._switch_theme("heavenly")

    @on(Button.Pressed, "#theme-btn-infernal")
    def theme_infernal(self): self._switch_theme("infernal")

    # -- Sign / Verify pane ----------------------------------------------------
    def _sign_verify_pane(self):
        sec = gpg_sec_keys()
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("Clearsign",    "sign"),
                    ("Detached sign","detach"),
                    ("Verify",       "verify"),
                ], id="sv-mode", allow_blank=False, value="sign"),
                Label("Key:"),
                Select([("(auto)", "")] + [(uid, fp) for uid, fp in sec],
                       id="sv-key", allow_blank=False),
                Label("Passphrase:"), Input(password=True, id="sv-pass"),
                Horizontal(
                    Button("Run",   id="btn-sv",     variant="success"),
                    Button("Clear", id="btn-sv-clr", variant="default"),
                    classes="btn-row",
                ),
                Button("XMR Timestamp", id="btn-xmr-ts-sv", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Input:",  classes="section-label"), SafeTextArea("", id="sv-in"),
                Label("Output:", classes="section-label"),
                SafeTextArea("", id="sv-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # -- PQC Sign pane ---------------------------------------------------------
    def _pqcsign_pane(self):
        sec = gpg_sec_keys()
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("ML-DSA-65 Keygen     · NIST L3 · 192-bit PQ",  "mldsa-gen"),
                    ("ML-DSA-65 Sign       · NIST L3 · 192-bit PQ",  "mldsa-sign"),
                    ("ML-DSA-65 Verify     · NIST L3 · 192-bit PQ",  "mldsa-verify"),
                    ("PGP + ML-DSA-65 Hybrid Sign · L3 + 128-bit",   "hybrid-sign"),
                    ("PGP + ML-DSA-65 Hybrid Verify",                 "hybrid-verify"),
                ], id="pqs-mode", allow_blank=False, value="mldsa-gen"),
                Label("PGP key (hybrid sign):"),
                Select(
                    [("(auto)", "")] + [(uid, fp) for uid, fp in sec],
                    id="pqs-pgp-key", allow_blank=False,
                ),
                Label("PGP passphrase:"), Input(password=True, id="pqs-pgp-pass"),
                Label("ML-DSA-65 private key:", id="pqs-priv-key-label"),
                SafeTextArea("", id="pqs-priv-key"),
                Label("ML-DSA-65 public key:", id="pqs-pub-key-label"),
                SafeTextArea("", id="pqs-pub-key"),
                Horizontal(
                    Button("Run",   id="btn-pqs",     variant="success"),
                    Button("Clear", id="btn-pqs-clr", variant="default"),
                    classes="btn-row",
                ),
                Button("XMR Timestamp", id="btn-xmr-ts-pqs", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Input / message:", classes="section-label"),
                SafeTextArea("", id="pqs-in"),
                Label("Output:", classes="section-label"),
                SafeTextArea("", id="pqs-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    @on(Select.Changed, "#pqs-mode")
    def pqs_mode_changed(self, event: Select.Changed) -> None:
        verify = event.value == "mldsa-verify"
        self.query_one("#pqs-priv-key-label", Label).update(
            "ML-DSA-65 signature (verify):" if verify else "ML-DSA-65 private key:"
        )
        self.query_one("#pqs-pub-key-label", Label).update(
            "ML-DSA-65 public key (verify):" if verify else "ML-DSA-65 public key:"
        )

    # -- Deadman Storage pane --------------------------------------------------
    def _deadman_pane(self):
        pub = gpg_pub_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no GPG keys)", "")]
        return Horizontal(
            Vertical(
                Label("Gateway (.onion):"),
                Input(value=f"http://{_DM_ONION}", id="dm-gateway"),
                Label("Tor SOCKS5 proxy:"),
                Input(value="127.0.0.1:9050", id="dm-proxy"),
                Label("GPG signing key:"),
                Select(pub_opts, id="dm-gpg-key", allow_blank=False),
                Button("Generate Mnemonic", id="btn-dm-gen",    variant="default"),
                Button("Create Vault",      id="btn-dm-create", variant="success"),
                Button("Clear",             id="btn-dm-clr",    variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Mnemonic (write this down — never stored):",
                      classes="section-label"),
                SafeTextArea("", id="dm-mnemonic", classes="output-area"),
                Label("Output:", classes="section-label"),
                SafeTextArea("", id="dm-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # -- File encrypt/decrypt pane ---------------------------------------------
    def _file_pane(self):
        pub = gpg_pub_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("GPG Encrypt · OpenPGP",                              "gpg-enc"),
                    ("GPG Decrypt · OpenPGP",                              "gpg-dec"),
                    ("X25519+ML-KEM-768 Encrypt · NIST L3 · 192-bit PQ",  "pqc-enc"),
                    ("X25519+ML-KEM-768 Decrypt · NIST L3 · 192-bit PQ",  "pqc-dec"),
                ], id="file-mode", allow_blank=False, value="gpg-enc"),
                Label("Source file:"),
                Input(placeholder="/path/to/file", id="file-src"),
                Label("Dest file (optional):"),
                Input(placeholder="leave blank = auto", id="file-dst"),
                Label("Recipient/key:"),
                Select(pub_opts, id="file-key", allow_blank=False),
                Label("Passphrase:"), Input(password=True, id="file-pass"),
                Label("PQC key file:"),
                Input(placeholder="/path/to/priv.key or pub.key", id="file-pqc-key"),
                Horizontal(
                    Button("Run",   id="btn-file",     variant="success"),
                    Button("Clear", id="btn-file-clr", variant="default"),
                    classes="btn-row",
                ),
                id="sidebar",
            ),
            Vertical(
                Label("Status/Output:", classes="section-label"),
                SafeTextArea("", id="file-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        lines = ["GPG PUBLIC KEYS", "="*50]
        for uid, fp in pub:
            lines += [f"  {uid}", f"  {fp}", ""]
        lines += ["", "GPG SECRET KEYS", "="*50]
        for uid, fp in sec:
            lines += [f"  {uid}", f"  {fp}", ""]
        if not pub and not sec:
            lines += ["  (no keys found  import with: gpg --import keyfile.gpg)", ""]
        lines += [f"\nGPG home: {GPG_HOME}"]
        return "\n".join(lines)

    # -- Merged pane: Encrypt (PGP + PQC) -------------------------------------
    def _enc_merged_pane(self):
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        return Vertical(
            Horizontal(
                Label("Mode:"),
                Select([("PGP Encrypt · OpenPGP", "pgp"), ("X25519+ML-KEM-768 Encrypt · NIST L3 · 192-bit PQ", "pqc")],
                       id="enc-mode", allow_blank=False, value="pgp"),
                classes="mode-bar",
            ),
            Horizontal(
                Vertical(
                    Label("Recipients (multi-select):"),
                    SelectionList(*pub_opts, id="enc-recipient"),
                    Label("Sign with (optional):"),
                    Select([("(none)", "")] + [(uid, fp) for uid, fp in sec],
                           id="enc-signer", allow_blank=False),
                    Label("Passphrase (signing):"), Input(password=True, id="enc-pass"),
                    Horizontal(
                        Button("Encrypt", id="btn-enc",     variant="success"),
                        Button("Clear",   id="btn-enc-clr", variant="default"),
                        classes="btn-row",
                    ),
                    id="sidebar",
                ),
                Vertical(
                    Label("Plaintext:",   classes="section-label"), SafeTextArea("", id="enc-in"),
                    Label("Ciphertext:", classes="section-label"),
                    SafeTextArea("", id="enc-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="enc-section-pgp", classes="tab-section",
            ),
            Horizontal(
                Vertical(
                    Label("Mode:"),
                    Select([
                        ("Encrypt",          "enc"),
                        ("Decrypt",          "dec"),
                        ("Generate keypair", "gen"),
                    ], id="pqc-mode", allow_blank=False, value="enc"),
                    Label("Public key (paste key or full bundle):"),  SafeTextArea("", id="pqc-pub-key"),
                    Label("Private key (decrypt):"),
                    Input(placeholder="/path/or/paste below", id="pqc-priv-path"),
                    SafeTextArea("", id="pqc-priv-key"),
                    Horizontal(
                        Button("Run",   id="btn-pqc",     variant="success"),
                        Button("Clear", id="btn-pqc-clr", variant="default"),
                        classes="btn-row",
                    ),
                    id="sidebar",
                ),
                Vertical(
                    Label("Input:",  classes="section-label"), SafeTextArea("", id="pqc-in"),
                    Label("Output:", classes="section-label"),
                    SafeTextArea("", id="pqc-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="enc-section-pqc", classes="tab-section hidden",
            ),
            classes="merged-pane",
        )

    @on(Select.Changed, "#enc-mode")
    def enc_mode_changed(self, event: Select.Changed) -> None:
        self.query_one("#enc-section-pgp").display = (event.value == "pgp")
        self.query_one("#enc-section-pqc").display = (event.value == "pqc")

    # -- Merged pane: Decrypt (PGP + Batch + Symmetric) -----------------------
    def _dec_merged_pane(self):
        sec = gpg_sec_keys()
        return Vertical(
            Horizontal(
                Label("Mode:"),
                Select([
                    ("PGP Decrypt",   "pgp"),
                    ("Batch Decrypt", "batch"),
                    ("Symmetric",     "sym"),
                ], id="dec-mode", allow_blank=False, value="pgp"),
                classes="mode-bar",
            ),
            Horizontal(
                Vertical(
                    Label("Key (auto-detect):"),
                    Select([("(auto)", "")] + [(uid, fp) for uid, fp in sec],
                           id="dec-key", allow_blank=False),
                    Label("Passphrase:"), Input(password=True, id="dec-pass"),
                    Horizontal(
                        Button("Decrypt", id="btn-dec",     variant="success"),
                        Button("Clear",   id="btn-dec-clr", variant="default"),
                        classes="btn-row",
                    ),
                    id="sidebar",
                ),
                Vertical(
                    Label("Ciphertext (paste):", classes="section-label"),
                    SafeTextArea("", id="dec-in"),
                    Label("Plaintext:", classes="section-label"),
                    SafeTextArea("", id="dec-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="dec-section-pgp", classes="tab-section",
            ),
            Horizontal(
                Vertical(
                    Label("Passphrase (GPG):"), Input(password=True, id="batch-pass"),
                    Label("PQC key files (one path per line):"),
                    SafeTextArea("", id="batch-pqc-keys", classes="batch-pqc-keys"),
                    Label("Separator:"), Input(value="-"*20, id="batch-sep"),
                    Horizontal(
                        Button("Decrypt All", id="btn-batch",     variant="success"),
                        Button("Clear",       id="btn-batch-clr", variant="default"),
                        classes="btn-row",
                    ),
                    id="sidebar",
                ),
                Vertical(
                    Label("Paste PGP/PQC blocks here:", classes="section-label"),
                    SafeTextArea("", id="batch-in"),
                    Label("Results:", classes="section-label"),
                    SafeTextArea("", id="batch-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="dec-section-batch", classes="tab-section hidden",
            ),
            Horizontal(
                Vertical(
                    Label("Mode:"),
                    Select([
                        ("Encrypt", "enc"),
                        ("Decrypt", "dec"),
                    ], id="sym-mode", allow_blank=False, value="enc"),
                    Label("Passphrase:"),   Input(password=True, id="sym-pass"),
                    Label("Confirm pass:"), Input(password=True, id="sym-pass2"),
                    Label("Cipher:"),
                    Select([
                        ("AES-256 (default)", "AES256"),
                        ("Camellia-256",      "CAMELLIA256"),
                        ("Twofish",           "TWOFISH"),
                    ], id="sym-cipher", allow_blank=False, value="AES256"),
                    Horizontal(
                        Button("Run",   id="btn-sym",     variant="success"),
                        Button("Clear", id="btn-sym-clr", variant="default"),
                        classes="btn-row",
                    ),
                    id="sidebar",
                ),
                Vertical(
                    Label("Input:",  classes="section-label"), SafeTextArea("", id="sym-in"),
                    Label("Output:", classes="section-label"),
                    SafeTextArea("", id="sym-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="dec-section-sym", classes="tab-section hidden",
            ),
            classes="merged-pane",
        )

    @on(Select.Changed, "#dec-mode")
    def dec_mode_changed(self, event: Select.Changed) -> None:
        self.query_one("#dec-section-pgp").display   = (event.value == "pgp")
        self.query_one("#dec-section-batch").display = (event.value == "batch")
        self.query_one("#dec-section-sym").display   = (event.value == "sym")

    # -- Merged pane: Keys (Key List + Generate) -------------------------------
    def _keys_merged_pane(self):
        return Vertical(
            Horizontal(
                Label("Mode:"),
                Select([("Key List", "list"), ("Generate Key", "gen")],
                       id="keys-mode", allow_blank=False, value="list"),
                classes="mode-bar",
            ),
            VerticalScroll(
                SafeTextArea(self._keys_text(), id="keys-text", read_only=True),
                Button("Refresh", id="btn-keys-refresh", variant="default"),
                Label("Keyserver lookup:", classes="section-label"),
                Input(placeholder="email or fingerprint", id="ks-query"),
                Button("Search",         id="btn-ks-search", variant="default"),
                Button("Fetch & Import", id="btn-ks-fetch",  variant="success"),
                SafeTextArea("", id="ks-out", read_only=True),
                Label("Import key (paste block):", classes="section-label"),
                SafeTextArea("", id="keys-import-text"),
                Button("Import", id="btn-keys-import", variant="success"),
                SafeTextArea("", id="keys-import-out", read_only=True),
                Label("Export PGP key:", classes="section-label"),
                Input(placeholder="fingerprint or email", id="keys-export-id"),
                Input(placeholder="passphrase (required for secret key export)", password=True, id="keys-export-pass"),
                Button("Export Public", id="btn-keys-export-pub", variant="default"),
                Button("Export Secret", id="btn-keys-export-sec", variant="warning"),
                SafeTextArea("", id="keys-export-out", read_only=True),
                Label("Dump hybrid signing key bundle (PGP + ML-DSA-65):", classes="section-label"),
                Input(placeholder="PGP fingerprint or email", id="bundle-dump-pgp-id"),
                Input(placeholder="Path to ML-DSA-65 key file (contains public or private block)", id="bundle-dump-mldsa-path"),
                Input(placeholder="PGP passphrase (required for private bundle)", password=True, id="bundle-dump-pass"),
                Horizontal(
                    Button("Public Bundle",  id="btn-bundle-pub",  variant="default"),
                    Button("Private Bundle", id="btn-bundle-priv", variant="warning"),
                    Button("Full Bundle",    id="btn-bundle-full", variant="error"),
                ),
                SafeTextArea("", id="bundle-dump-out", read_only=True),
                id="keys-section-list", classes="tab-section",
            ),
            Horizontal(
                Vertical(
                    Label("Key type:"),
                    Select([
                        ("Ed25519  · 128-bit · EdDSA",                              "ed25519"),
                        ("RSA-4096 · 140-bit classical",                             "rsa4096"),
                        ("RSA-2048 · 112-bit classical",                             "rsa2048"),
                        ("X25519+ML-KEM-768 · NIST L3 · 192-bit PQ enc",            "pqc"),
                        ("PGP+ML-DSA-65 hybrid sign · Ed25519 + NIST L3",           "pgp-mldsa"),
                        ("PGP+X25519+ML-KEM-768 hybrid · new both · NIST L3",       "pgp-pqc-new"),
                        ("PGP+X25519+ML-KEM-768 hybrid · existing PGP + new PQC",   "pgp-pqc-existing"),
                        ("PGP+X25519+ML-KEM-768 hybrid · paste both keys",          "pgp-pqc-paste"),
                    ], id="kg-type", allow_blank=False, value="ed25519"),
                    Label("Real name:"),    Input(placeholder="Alice", id="kg-name"),
                    Label("Email (optional):"), Input(placeholder="alice@example.com", id="kg-email"),
                    Label("Passphrase:"),   Input(password=True, id="kg-pass"),
                    Label("Confirm pass:"), Input(password=True, id="kg-pass2"),
                    Label("Expires (GPG):"),
                    Select([
                        ("Never",    "0"),
                        ("1 year",   "1y"),
                        ("2 years",  "2y"),
                        ("6 months", "6m"),
                    ], id="kg-expire", allow_blank=False, value="0"),
                    # shown only for pgp-pqc-existing
                    Label("Existing PGP key:", id="kg-existing-label", classes="hidden section-label"),
                    Select([], id="kg-existing-pgp", allow_blank=True, classes="hidden"),
                    # shown only for pgp-pqc-paste
                    Label("Paste PGP private key:", id="kg-paste-pgp-label", classes="hidden section-label"),
                    SafeTextArea("", id="kg-paste-pgp", classes="hidden"),
                    Label("Paste PQC private key:", id="kg-paste-pqc-label", classes="hidden section-label"),
                    SafeTextArea("", id="kg-paste-pqc", classes="hidden"),
                    Button("Generate", id="btn-kg", variant="success"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Output:", classes="section-label"),
                    SafeTextArea("", id="kg-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="keys-section-gen", classes="tab-section hidden",
            ),
            classes="merged-pane",
        )

    @on(Select.Changed, "#keys-mode")
    def keys_mode_changed(self, event: Select.Changed) -> None:
        self.query_one("#keys-section-list").display = (event.value == "list")
        self.query_one("#keys-section-gen").display  = (event.value == "gen")

    @on(Select.Changed, "#kg-type")
    def kg_type_changed(self, event: Select.Changed) -> None:
        v = event.value
        existing = v == "pgp-pqc-existing"
        paste    = v == "pgp-pqc-paste"
        # name/email/pass/expire only needed for new-key types
        needs_identity = v not in ("pgp-pqc-existing", "pgp-pqc-paste")
        for wid in ("#kg-name", "#kg-email", "#kg-pass", "#kg-pass2", "#kg-expire"):
            self.query_one(wid).display = needs_identity
        for wid in ("#kg-existing-label", "#kg-existing-pgp"):
            self.query_one(wid).display = existing
        for wid in ("#kg-paste-pgp-label", "#kg-paste-pgp", "#kg-paste-pqc-label", "#kg-paste-pqc"):
            self.query_one(wid).display = paste
        if existing:
            # populate the select with current GPG secret keys
            sec = gpg_sec_keys()
            opts = [(uid, fp) for uid, fp in sec] if sec else [("(no secret keys)", "")]
            sel = self.query_one("#kg-existing-pgp", Select)
            sel.set_options(opts)

    # -- Helpers ---------------------------------------------------------------
    def set_status(self, msg: str, ok: bool = True):
        bar = self.query_one("#status-bar", Label)
        bar.update(msg)
        bar.remove_class("status-ok", "status-err")
        bar.add_class("status-ok" if ok else "status-err")

    def action_tab(self, tab_id: str):
        self.query_one("#tabs", TabbedContent).active = tab_id

    def _xmr_timestamp_into(self, target_id: str):
        """Fetch latest XMR block and prepend it into target TextArea."""
        self.set_status("Fetching XMR block...")
        def fetch():
            text = xmr_latest_block()
            def apply():
                ta = self.query_one(target_id, TextArea)
                existing = ta.text.strip()
                ta.load_text(text + ("\n\n" + existing if existing else ""))
                self.set_status("XMR block fetched.")
            self.call_from_thread(apply)
        threading.Thread(target=fetch, daemon=True).start()

    @on(Button.Pressed, "#btn-xmr-ts-sv")
    def xmr_ts_sv(self):  self._xmr_timestamp_into("#sv-in")

    @on(Button.Pressed, "#btn-xmr-ts-pqs")
    def xmr_ts_pqs(self): self._xmr_timestamp_into("#pqs-in")

    _RESIZE_STEP = 3
    _RESIZE_MIN  = 3

    def action_resize_up(self):
        """Alt+Up: make focused TextArea taller."""
        w = self.focused
        if isinstance(w, TextArea):
            current = w.styles.height
            h = int(current.value) if (current and current.unit.name == "CELLS") else 10
            w.styles.height = max(self._RESIZE_MIN, h + self._RESIZE_STEP)

    def action_resize_down(self):
        """Alt+Down: make focused TextArea shorter."""
        w = self.focused
        if isinstance(w, TextArea):
            current = w.styles.height
            h = int(current.value) if (current and current.unit.name == "CELLS") else 10
            w.styles.height = max(self._RESIZE_MIN, h - self._RESIZE_STEP)

    def action_resize_left(self):
        """Alt+Left: narrow the sidebar."""
        for sb in self.query("#sidebar"):
            current = sb.styles.width
            w = int(current.value) if (current and current.unit.name == "CELLS") else 32
            sb.styles.width = max(16, w - self._RESIZE_STEP)

    def action_resize_right(self):
        """Alt+Right: widen the sidebar."""
        for sb in self.query("#sidebar"):
            current = sb.styles.width
            w = int(current.value) if (current and current.unit.name == "CELLS") else 32
            sb.styles.width = min(80, w + self._RESIZE_STEP)

    def _refresh_all_key_selects(self):
        """Rebuild all key-related Select/SelectionList widgets after keyring changes."""
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        sec_opts  = [("(none)", "")] + [(uid, fp) for uid, fp in sec]
        sec_auto  = [("(auto)", "")] + [(uid, fp) for uid, fp in sec]

        # enc-recipient is SelectionList
        try:
            sl = self.query_one("#enc-recipient", SelectionList)
            sl.clear_options()
            sl.add_options(pub_opts)
        except Exception:
            pass

        for widget_id, opts in [
            ("#enc-signer",   sec_opts),
            ("#dec-key",      sec_auto),
            ("#sv-key",       sec_auto),
            ("#file-key",     pub_opts),
            ("#pqs-pgp-key",  sec_auto),
            ("#kg-existing-pgp", sec_opts),
        ]:
            try:
                self.query_one(widget_id, Select).set_options(opts)
            except Exception:
                pass

        try:
            self.query_one("#keys-text", SafeTextArea).load_text(self._keys_text())
        except Exception:
            pass

        self.set_status("Keys refreshed.")

    # -- Button handlers -------------------------------------------------------
    @on(Button.Pressed, "#btn-enc")
    def do_encrypt(self):
        pt   = self.query_one("#enc-in",        TextArea).text.strip()
        recs = self.query_one("#enc-recipient",  SelectionList).selected
        sig  = self.query_one("#enc-signer",     Select).value
        pp   = self.query_one("#enc-pass",       Input).value
        if not pt:   return self.set_status("No plaintext.", ok=False)
        if not recs: return self.set_status("Select at least one recipient.", ok=False)
        kw = dict(recipients=recs, always_trust=True, armor=True)
        if sig: kw.update(sign=sig, passphrase=pp or None)
        r = gpg.encrypt(pt, **kw)
        if r.ok:
            self.query_one("#enc-out", TextArea).load_text(str(r))
            self.set_status(f"Encrypted OK: {r.status}")
        else:
            self.query_one("#enc-out", TextArea).load_text(f"ERROR:\n{r.stderr}")
            self.set_status(f"Encrypt failed: {r.status}", ok=False)

    @on(Button.Pressed, "#btn-dec")
    def do_decrypt(self):
        ct = self.query_one("#dec-in", TextArea).text.strip()
        pp = self.query_one("#dec-pass", Input).value
        if not ct: return self.set_status("No ciphertext.", ok=False)
        r = gpg.decrypt(ct, passphrase=pp or None, always_trust=True)
        if r.ok:
            self.query_one("#dec-out", TextArea).load_text(str(r))
            self.set_status(f"Decrypted OK, signed by: {r.username or 'unsigned'}")
        else:
            self.query_one("#dec-out", TextArea).load_text(f"ERROR:\n{r.stderr}")
            self.set_status(f"Decrypt failed: {r.status}", ok=False)

    @on(Button.Pressed, "#btn-batch")
    def do_batch(self):
        raw = self.query_one("#batch-in",   TextArea).text
        pp  = self.query_one("#batch-pass", Input).value
        sep = self.query_one("#batch-sep",  Input).value
        # Multi-key: one file path per line
        key_paths = [p.strip() for p in
                     self.query_one("#batch-pqc-keys", TextArea).text.splitlines()
                     if p.strip()]

        pqc_privs = []
        for path in key_paths:
            try:
                pqc_privs.append(hybrid_crypto.parse_private_key(Path(path).read_text()))
            except Exception as e:
                self.set_status(f"PQC key load failed ({path}): {e}", ok=False)
                return

        pgp_blocks = PGP_BLOCK_RE.findall(raw)
        hyb_blocks = HYB_BLOCK_RE.findall(raw)
        total = len(pgp_blocks) + len(hyb_blocks)
        if not total:
            return self.set_status("No PGP or PQC blocks found.", ok=False)

        results  = []
        ok_count = 0

        for i, block in enumerate(pgp_blocks, 1):
            r = gpg.decrypt(block, passphrase=pp or None, always_trust=True)
            if r.ok:
                ok_count += 1
                results.append(f"[GPG {i}/{len(pgp_blocks)}]  OK  ({r.username or 'unsigned'})\n{str(r)}")
            else:
                results.append(f"[GPG {i}/{len(pgp_blocks)}]  FAIL  {r.status}\n{r.stderr.strip()}")

        for i, block in enumerate(hyb_blocks, 1):
            if not pqc_privs:
                results.append(f"[PQC {i}/{len(hyb_blocks)}]  SKIP  No PQC private key provided")
                continue
            decrypted = False
            for priv in pqc_privs:
                try:
                    pt = hybrid_crypto.decrypt(block, priv)
                    ok_count += 1
                    results.append(f"[PQC {i}/{len(hyb_blocks)}]  OK\n{pt}")
                    decrypted = True
                    break
                except Exception:
                    continue
            if not decrypted:
                results.append(f"[PQC {i}/{len(hyb_blocks)}]  FAIL  None of the {len(pqc_privs)} key(s) worked")

        self.query_one("#batch-out", TextArea).load_text(f"\n{sep}\n".join(results))
        self.set_status(f"Batch: {ok_count}/{total} decrypted OK")

    @staticmethod
    def _gpg_batch(key_type: str, name: str, email: str, expire: str, passphrase) -> str:
        """Build a correct GPG batch key-gen input string, bypassing gen_key_input's
        broken EDDSA handling (it adds Key-Length which is invalid for curve keys)."""
        lines = []
        if key_type == "EDDSA":
            lines += [
                "Key-Type: EDDSA",
                "Key-Curve: Ed25519",
                "Key-Usage: sign",
                "Subkey-Type: ECDH",
                "Subkey-Curve: Curve25519",
                "Subkey-Usage: encrypt",
            ]
        else:
            lines += [f"Key-Type: {key_type}"]
        lines.append(f"Name-Real: {name}")
        if email:
            lines.append(f"Name-Email: {email}")
        lines.append(f"Expire-Date: {expire or '0'}")
        if passphrase:
            lines.append(f"Passphrase: {passphrase}")
        else:
            lines.append("%no-protection")
        lines.append("%commit")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _identity(name: str, email: str) -> str:
        return f"{name} <{email}>" if email else name

    @staticmethod
    def _extract_pqc_pub(text: str) -> str:
        """Extract X25519+ML-KEM-768 PUBLIC KEY block from a full bundle or return text as-is."""
        if "BEGIN X25519+ML-KEM-768 PUBLIC KEY BUNDLE" in text:
            m = re.search(
                r"(-----BEGIN X25519\+ML-KEM-768 PUBLIC KEY-----.*?-----END X25519\+ML-KEM-768 PUBLIC KEY-----)",
                text, re.DOTALL
            )
            if m:
                return m.group(1).strip()
        return text

    @on(Button.Pressed, "#btn-kg")
    def do_keygen(self):
        ktype  = self.query_one("#kg-type",   Select).value
        out    = self.query_one("#kg-out", TextArea)

        # ── PGP + PQC-E hybrid: generate both from scratch ────────────────────
        if ktype == "pgp-pqc-new":
            name   = self.query_one("#kg-name",  Input).value.strip()
            email  = self.query_one("#kg-email", Input).value.strip()
            pp     = self.query_one("#kg-pass",  Input).value
            pp2    = self.query_one("#kg-pass2", Input).value
            expire = self.query_one("#kg-expire", Select).value
            if not name:
                return self.set_status("Name required.", ok=False)
            if pp != pp2:
                return self.set_status("Passphrases don't match.", ok=False)
            try:
                inp = self._gpg_batch("EDDSA", name, email, expire, pp or None)
                self.set_status("Generating PGP component...")
                key = gpg.gen_key(inp)
                if not key.fingerprint:
                    out.load_text(f"GPG key generation failed.\n{key.stderr}")
                    return self.set_status("GPG key generation failed.", ok=False)
                pgp_pub = gpg.export_keys(key.fingerprint, armor=True)
                pqc_pub, pqc_priv = hybrid_crypto.generate_keypair()
                pqc_pub_arm = hybrid_crypto.armor_public_key(pqc_pub)
                combined_pub = (
                    f"-----BEGIN X25519+ML-KEM-768 PUBLIC KEY BUNDLE-----\n"
                    f"PGP-Fingerprint: {key.fingerprint}\n"
                    f"Identity: {self._identity(name, email)}\n\n"
                    f"{pgp_pub}\n\n"
                    f"{pqc_pub_arm}\n"
                    f"-----END X25519+ML-KEM-768 PUBLIC KEY BUNDLE-----"
                )
                result = (
                    f"PGP + X25519+ML-KEM-768 Hybrid Key Bundle\n"
                    f"Identity: {self._identity(name, email)}\n"
                    f"{'='*50}\n\n"
                    f"--- PGP COMPONENT (Ed25519 · 128-bit) ---\n"
                    f"Fingerprint: {key.fingerprint}\n\n"
                    f"{pgp_pub}\n\n"
                    f"{'='*50}\n"
                    f"--- X25519+ML-KEM-768 COMPONENT (NIST L3 · 192-bit PQ) ---\n\n"
                    f"{pqc_pub_arm}\n\n"
                    f"{'='*50}\n"
                    f"--- COMBINED PUBLIC KEY (share this) ---\n\n"
                    f"{combined_pub}\n\n"
                    f"{'='*50}\n"
                    f"X25519+ML-KEM-768 PRIVATE KEY (do not share):\n\n"
                    f"{hybrid_crypto.armor_private_key(pqc_priv)}"
                )
                out.load_text(result)
                self.set_status(f"PGP+X25519+ML-KEM-768 bundle generated: {key.fingerprint[-16:]}")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"Keygen failed: {e}", ok=False)
            return

        # ── PGP + PQC-E hybrid: existing PGP key + new PQC half ───────────────
        if ktype == "pgp-pqc-existing":
            fp = self.query_one("#kg-existing-pgp", Select).value
            if not fp:
                return self.set_status("Select an existing PGP key.", ok=False)
            try:
                pgp_pub = gpg.export_keys(fp, armor=True)
                pqc_pub, pqc_priv = hybrid_crypto.generate_keypair()
                uid = next((u for k in gpg.list_keys() if k["fingerprint"] == fp for u in k["uids"]), fp)
                pqc_pub_arm = hybrid_crypto.armor_public_key(pqc_pub)
                combined_pub = (
                    f"-----BEGIN X25519+ML-KEM-768 PUBLIC KEY BUNDLE-----\n"
                    f"PGP-Fingerprint: {fp}\n"
                    f"Identity: {uid}\n\n"
                    f"{pgp_pub}\n\n"
                    f"{pqc_pub_arm}\n"
                    f"-----END X25519+ML-KEM-768 PUBLIC KEY BUNDLE-----"
                )
                result = (
                    f"PGP + X25519+ML-KEM-768 Hybrid Key Bundle\n"
                    f"Identity: {uid}\n"
                    f"{'='*50}\n\n"
                    f"--- PGP COMPONENT (existing · 128-bit) ---\n"
                    f"Fingerprint: {fp}\n\n"
                    f"{pgp_pub}\n\n"
                    f"{'='*50}\n"
                    f"--- X25519+ML-KEM-768 COMPONENT (NIST L3 · 192-bit PQ) ---\n\n"
                    f"{pqc_pub_arm}\n\n"
                    f"{'='*50}\n"
                    f"--- COMBINED PUBLIC KEY (share this) ---\n\n"
                    f"{combined_pub}\n\n"
                    f"{'='*50}\n"
                    f"X25519+ML-KEM-768 PRIVATE KEY (do not share):\n\n"
                    f"{hybrid_crypto.armor_private_key(pqc_priv)}"
                )
                out.load_text(result)
                self.set_status(f"PGP+X25519+ML-KEM-768 bundle generated from existing PGP key {fp[-16:]}")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"Keygen failed: {e}", ok=False)
            return

        # ── PGP + X25519+ML-KEM-768: paste both existing keys ─────────────────
        if ktype == "pgp-pqc-paste":
            pgp_block = self.query_one("#kg-paste-pgp", TextArea).text.strip()
            pqc_block = self.query_one("#kg-paste-pqc", TextArea).text.strip()
            if not pgp_block:
                return self.set_status("Paste a PGP private key block.", ok=False)
            if not pqc_block:
                return self.set_status("Paste an X25519+ML-KEM-768 private key block.", ok=False)
            try:
                result = (
                    f"PGP + X25519+ML-KEM-768 Hybrid Key Bundle (from existing keys)\n"
                    f"{'='*50}\n\n"
                    f"--- PGP COMPONENT ---\n\n"
                    f"{pgp_block}\n\n"
                    f"{'='*50}\n"
                    f"--- X25519+ML-KEM-768 COMPONENT ---\n\n"
                    f"{pqc_block}"
                )
                out.load_text(result)
                self.set_status("PGP+X25519+ML-KEM-768 bundle assembled from pasted keys.")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"Bundle failed: {e}", ok=False)
            return

        name   = self.query_one("#kg-name",   Input).value.strip()
        email  = self.query_one("#kg-email",  Input).value.strip()
        pp     = self.query_one("#kg-pass",   Input).value
        pp2    = self.query_one("#kg-pass2",  Input).value
        expire = self.query_one("#kg-expire", Select).value

        if not name:
            return self.set_status("Name required.", ok=False)
        if pp != pp2:
            return self.set_status("Passphrases don't match.", ok=False)

        if ktype == "pgp-mldsa":
            try:
                inp = self._gpg_batch("EDDSA", name, email, expire, pp or None)
                self.set_status("Generating GPG component...")
                key = gpg.gen_key(inp)
                if not key.fingerprint:
                    out.load_text(f"GPG key generation failed.\n{key.stderr}")
                    return self.set_status("GPG key generation failed.", ok=False)
                pgp_pub = gpg.export_keys(key.fingerprint, armor=True)
                mldsa_pub, mldsa_priv = pqsign_crypto.generate_keypair()
                ident = self._identity(name, email)
                pub_bundle = (
                    f"-----BEGIN PGP+ML-DSA-65 SIGNING KEY BUNDLE-----\n"
                    f"PGP-Fingerprint: {key.fingerprint}\n"
                    f"Identity: {ident}\n\n"
                    f"{pgp_pub.strip()}\n\n"
                    f"{mldsa_pub.strip()}\n"
                    f"-----END PGP+ML-DSA-65 SIGNING KEY BUNDLE-----"
                )
                result = (
                    f"PGP + ML-DSA-65 Hybrid Signing Key Bundle\n"
                    f"Identity: {ident}\n"
                    f"{'='*50}\n\n"
                    f"--- PGP COMPONENT (Ed25519) ---\n"
                    f"Fingerprint: {key.fingerprint}\n\n"
                    f"{pgp_pub}\n\n"
                    f"{'='*50}\n"
                    f"--- ML-DSA-65 COMPONENT ---\n\n"
                    f"{mldsa_pub}\n\n"
                    f"{'='*50}\n"
                    f"--- COMBINED PUBLIC BUNDLE (paste this into Deadman) ---\n\n"
                    f"{pub_bundle}\n\n"
                    f"{'='*50}\n"
                    f"ML-DSA-65 PRIVATE KEY (do not share):\n\n"
                    f"{mldsa_priv}"
                )
                out.load_text(result)
                self.set_status(f"Hybrid signing key bundle generated: {key.fingerprint[-16:]}")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"Hybrid keygen failed: {e}", ok=False)
            return

        if ktype == "pqc":
            try:
                pub, priv = hybrid_crypto.generate_keypair()
                pub_arm  = hybrid_crypto.armor_public_key(pub)
                priv_arm = hybrid_crypto.armor_private_key(priv)
                result = (
                    f"X25519+ML-KEM-768 Encryption Key\n"
                    f"Identity: {name} <{email}>\n"
                    f"{'='*50}\n\n"
                    f"{pub_arm}\n\n"
                    f"{'='*50}\n"
                    f"X25519+ML-KEM-768 PRIVATE KEY (do not share):\n\n"
                    f"{priv_arm}"
                )
                out.load_text(result)
                self.set_status("X25519+ML-KEM-768 keypair generated. Save private key securely!")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"PQC keygen failed: {e}", ok=False)
            return

        # GPG key
        key_map = {"ed25519": ("EDDSA",""), "rsa4096": ("RSA","4096"), "rsa2048": ("RSA","2048")}
        key_type, key_len = key_map[ktype]
        if key_type == "EDDSA":
            inp = self._gpg_batch("EDDSA", name, email, expire, pp or None)
        else:
            inp_kw = dict(
                key_type=key_type, name_real=name, name_email=email,
                expire_date=expire, passphrase=pp or None,
                key_length=int(key_len),
            )
            inp = gpg.gen_key_input(**inp_kw)
        self.set_status("Generating key (may take a moment)")
        key = gpg.gen_key(inp)
        if key.fingerprint:
            out.load_text(
                f"GPG key generated!\n"
                f"Type:        {ktype}\n"
                f"Identity:    {self._identity(name, email)}\n"
                f"Fingerprint: {key.fingerprint}\n"
                f"Expires:     {expire if expire != '0' else 'never'}\n\n"
                f"Export public key:\n  gpg --armor --export {key.fingerprint}\n\n"
                f"Export private key:\n  gpg --armor --export-secret-keys {key.fingerprint}"
            )
            self.set_status(f"Key generated: {key.fingerprint[-16:]}")
        else:
            out.load_text(f"Key generation failed.\n{key.stderr}")
            self.set_status("Key generation failed.", ok=False)

    @on(Button.Pressed, "#btn-pqc")
    def do_pqc(self):
        mode = self.query_one("#pqc-mode", Select).value
        inp  = self.query_one("#pqc-in",   TextArea).text.strip()
        out  = self.query_one("#pqc-out",  TextArea)

        if mode == "gen":
            try:
                pub, priv = hybrid_crypto.generate_keypair()
                out.load_text(
                    f"X25519 + ML-KEM-768 Hybrid Keypair\n{'='*50}\n\n"
                    f"{hybrid_crypto.armor_public_key(pub)}\n\n"
                    f"{'='*50}\nPRIVATE KEY (do not share):\n\n"
                    f"{hybrid_crypto.armor_private_key(priv)}"
                )
                self.set_status("PQC keypair generated.")
            except Exception as e:
                self.set_status(f"Keygen error: {e}", ok=False)
            return

        if mode == "enc":
            pub_text = self.query_one("#pqc-pub-key", TextArea).text.strip()
            if not pub_text: return self.set_status("Paste public key in left panel.", ok=False)
            if not inp:      return self.set_status("No plaintext to encrypt.", ok=False)
            try:
                pub = hybrid_crypto.parse_public_key(self._extract_pqc_pub(pub_text))
                ct  = hybrid_crypto.encrypt(inp, pub)
                out.load_text(ct)
                self.set_status("PQC encrypted OK.")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"PQC encrypt failed: {e}", ok=False)

        elif mode == "dec":
            priv_path = self.query_one("#pqc-priv-path", Input).value.strip()
            priv_text = self.query_one("#pqc-priv-key",  TextArea).text.strip()
            if priv_path:
                try: priv_text = Path(priv_path).read_text()
                except Exception as e:
                    return self.set_status(f"Key file error: {e}", ok=False)
            if not priv_text: return self.set_status("Paste private key.", ok=False)
            if not inp:       return self.set_status("No ciphertext to decrypt.", ok=False)
            try:
                priv = hybrid_crypto.parse_private_key(priv_text)
                pt   = hybrid_crypto.decrypt(inp, priv)
                out.load_text(pt)
                self.set_status("PQC decrypted OK.")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"PQC decrypt failed: {e}", ok=False)

    @on(Button.Pressed, "#btn-sv")
    def do_sign_verify(self):
        mode = self.query_one("#sv-mode", Select).value
        text = self.query_one("#sv-in",   TextArea).text.strip()
        key  = self.query_one("#sv-key",  Select).value
        pp   = self.query_one("#sv-pass", Input).value
        out  = self.query_one("#sv-out",  TextArea)

        if not text:
            return self.set_status("No input text.", ok=False)

        if mode in ("sign", "detach"):
            kw = dict(passphrase=pp or None, clearsign=(mode == "sign"))
            if mode == "detach":
                kw["detach"] = True
                kw["clearsign"] = False
            if key:
                kw["keyid"] = key
            result = gpg.sign(text, **kw)
            signed = str(result)
            if signed:
                out.load_text(signed)
                self.set_status(f"Signed OK: {result.status}")
            else:
                out.load_text(f"Signing failed.\nStatus: {result.status}\nStderr: {result.stderr}")
                self.set_status(f"Sign failed: {result.status}", ok=False)

        elif mode == "verify":
            result = gpg.verify(text)
            if result.valid:
                ts = ""
                try:
                    ts = datetime.datetime.utcfromtimestamp(float(result.timestamp)).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    ts = str(result.timestamp)
                out.load_text(
                    f"VALID signature\n"
                    f"User:      {result.username}\n"
                    f"Key ID:    {result.key_id}\n"
                    f"Timestamp: {ts}\n"
                    f"Status:    {result.status}"
                )
                self.set_status("Signature valid.")
            else:
                out.load_text(
                    f"INVALID / unverified\n"
                    f"Status: {result.status}\n"
                    f"Key ID: {result.key_id or '(unknown)'}"
                )
                self.set_status("Signature invalid or not found.", ok=False)

    @on(Button.Pressed, "#btn-pqs-clr")
    def pqs_clear(self):
        for wid in ("#pqs-in", "#pqs-out", "#pqs-priv-key", "#pqs-pub-key"):
            self.query_one(wid, TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-pqs")
    def do_pqcsign(self):
        mode     = self.query_one("#pqs-mode",     Select).value
        msg      = self.query_one("#pqs-in",       TextArea).text.strip()
        priv_txt = self.query_one("#pqs-priv-key", TextArea).text.strip()
        pub_txt  = self.query_one("#pqs-pub-key",  TextArea).text.strip()
        pgp_fp   = self.query_one("#pqs-pgp-key",  Select).value
        pgp_pp   = self.query_one("#pqs-pgp-pass", Input).value
        out      = self.query_one("#pqs-out",      TextArea)

        if mode == "mldsa-gen":
            try:
                pub, priv = pqsign_crypto.generate_keypair()
                info = pqsign_crypto.KEY_INFO
                out.load_text(
                    f"Algorithm : {info['algorithm']}\n"
                    f"Standard  : {info['standard']}\n"
                    f"Pub size  : {info['pub_bytes']} bytes\n"
                    f"Priv size : {info['priv_bytes']} bytes\n"
                    f"Sig size  : {info['sig_bytes']} bytes\n\n"
                    f"{pub}\n\n"
                    f"--- PRIVATE KEY (do not share) ---\n\n"
                    f"{priv}"
                )
                self.set_status("ML-DSA-65 keypair generated.")
            except Exception as e:
                self.set_status(f"Keygen error: {e}", ok=False)

        elif mode == "mldsa-sign":
            if not priv_txt:
                return self.set_status("Paste ML-DSA-65 private key.", ok=False)
            if not msg:
                return self.set_status("No message to sign.", ok=False)
            try:
                sig = pqsign_crypto.sign_message(priv_txt, msg)
                out.load_text(sig)
                self.set_status("Signed.")
            except Exception as e:
                self.set_status(f"Sign error: {e}", ok=False)

        elif mode == "mldsa-verify":
            if not pub_txt:
                return self.set_status("Paste ML-DSA-65 public key.", ok=False)
            sig_txt = msg  # input field holds the armored signature
            if not sig_txt:
                return self.set_status("Paste signature in Input field.", ok=False)
            # expect "message\n---\nsignature" or just signature if msg known
            # convention: input = original message; pub-key field = pub; priv-key field = sig
            sig_field = self.query_one("#pqs-priv-key", TextArea).text.strip()
            if not sig_field:
                return self.set_status("Paste signature in private key field.", ok=False)
            try:
                pqsign_crypto.verify_message(pub_txt, msg, sig_field)
                out.load_text("Signature valid.\nAlgorithm: ML-DSA-65 (NIST FIPS 204)")
                self.set_status("Signature valid.")
            except Exception as e:
                out.load_text(f"Invalid: {e}")
                self.set_status(f"Signature invalid: {e}", ok=False)

        elif mode == "hybrid-sign":
            if not priv_txt:
                return self.set_status("Paste ML-DSA-65 private key.", ok=False)
            if not msg:
                return self.set_status("No message to sign.", ok=False)
            if not pub_txt:
                return self.set_status("Paste ML-DSA-65 public key.", ok=False)
                return self.set_status("Paste ML-DSA-65 public key.", ok=False)
            try:
                out.load_text("Signing with PGP...")
                # PGP clearsign
                kw = dict(clearsign=True, passphrase=pgp_pp or None)
                if pgp_fp:
                    kw["keyid"] = pgp_fp
                pgp_result = gpg.sign(msg, **kw)
                if not str(pgp_result):
                    out.load_text(f"ERROR: PGP sign failed.\nStatus: {pgp_result.status}\nStderr: {pgp_result.stderr}")
                    return self.set_status(f"PGP sign failed: {pgp_result.status}", ok=False)
                out.load_text("PGP signed. Signing with ML-DSA-65...")
                # ML-DSA-65 signature
                mldsa_sig = pqsign_crypto.sign_message(priv_txt, msg)
                bundle = pqsign_crypto.make_hybrid_bundle(
                    str(pgp_result), mldsa_sig, pub_txt, msg
                )
                out.load_text(bundle)
                self.set_status("Hybrid signature bundle created.")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"Hybrid sign error: {e}", ok=False)

        elif mode == "hybrid-verify":
            bundle = msg
            if not bundle:
                return self.set_status("Paste hybrid bundle in Input field.", ok=False)
            try:
                result = pqsign_crypto.verify_hybrid_bundle(bundle, gpg)
                out.load_text(
                    f"Both signatures valid.\n\n"
                    f"PGP key ID : {result['pgp_info']['key_id']}\n"
                    f"PGP user   : {result['pgp_info']['username']}\n"
                    f"PGP status : {result['pgp_info']['status']}\n\n"
                    f"ML-DSA-65  : {result['mldsa_info']['algorithm']}\n"
                    f"Message    : {result['message']}"
                )
                self.set_status("Hybrid bundle verified.")
            except Exception as e:
                preview = bundle[:120].replace('\n', '↵')
                out.load_text(
                    f"Verification failed: {e}\n\n"
                    f"--- Input preview (first 120 chars) ---\n{preview}"
                )
                self.set_status(f"Hybrid verify failed: {e}", ok=False)

    @on(Button.Pressed, "#btn-file")
    def do_file(self):
        mode    = self.query_one("#file-mode",    Select).value
        src     = self.query_one("#file-src",     Input).value.strip()
        dst     = self.query_one("#file-dst",     Input).value.strip()
        fp      = self.query_one("#file-key",     Select).value
        pp      = self.query_one("#file-pass",    Input).value
        pqc_key = self.query_one("#file-pqc-key", Input).value.strip()
        out     = self.query_one("#file-out",     TextArea)

        if not src:
            return self.set_status("Source file required.", ok=False)
        if not Path(src).exists():
            return self.set_status(f"File not found: {src}", ok=False)

        if mode == "gpg-enc":
            if not dst:
                dst = src + ".gpg"
            cmd = ["gpg", "--output", dst, "--encrypt", "--recipient", fp,
                   "--armor", "--yes", src]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    out.load_text(f"Encrypted to: {dst}\n{r.stdout}")
                    self.set_status(f"GPG file encrypted  {Path(dst).name}")
                else:
                    out.load_text(f"GPG error:\n{r.stderr}")
                    self.set_status("GPG encrypt failed.", ok=False)
            except Exception as e:
                out.load_text(f"Error: {e}")
                self.set_status(str(e), ok=False)

        elif mode == "gpg-dec":
            if not dst:
                s = src
                for ext in (".gpg", ".asc", ".pgp"):
                    if s.endswith(ext):
                        dst = s[:-len(ext)]
                        break
                else:
                    dst = src + ".dec"
            cmd = ["gpg", "--output", dst, "--decrypt", "--yes",
                   "--passphrase-fd", "0", src]
            try:
                r = subprocess.run(cmd, input=pp, capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    out.load_text(f"Decrypted to: {dst}\n{r.stdout}")
                    self.set_status(f"GPG file decrypted  {Path(dst).name}")
                else:
                    out.load_text(f"GPG error:\n{r.stderr}")
                    self.set_status("GPG decrypt failed.", ok=False)
            except Exception as e:
                out.load_text(f"Error: {e}")
                self.set_status(str(e), ok=False)

        elif mode == "pqc-enc":
            if not pqc_key:
                return self.set_status("PQC public key file required.", ok=False)
            if not dst:
                dst = src + ".hybrid"
            try:
                pub_text = Path(pqc_key).read_text()
                pub      = hybrid_crypto.parse_public_key(self._extract_pqc_pub(pub_text))
                data     = Path(src).read_bytes()
                b64_data = base64.b64encode(data).decode("utf-8")
                ct = hybrid_crypto.encrypt(b64_data, pub)
                Path(dst).write_text(ct)
                out.load_text(f"PQC encrypted to: {dst}")
                self.set_status(f"PQC file encrypted  {Path(dst).name}")
            except Exception as e:
                out.load_text(f"Error: {e}")
                self.set_status(str(e), ok=False)

        elif mode == "pqc-dec":
            if not pqc_key:
                return self.set_status("PQC private key file required.", ok=False)
            if not dst:
                s = src
                if s.endswith(".hybrid"):
                    dst = s[:-7]
                else:
                    dst = src + ".dec"
            try:
                priv_text = Path(pqc_key).read_text()
                priv = hybrid_crypto.parse_private_key(priv_text)
                armored = Path(src).read_text()
                b64_data = hybrid_crypto.decrypt(armored, priv)
                file_bytes = base64.b64decode(b64_data)
                Path(dst).write_bytes(file_bytes)
                out.load_text(f"PQC decrypted to: {dst}")
                self.set_status(f"PQC file decrypted  {Path(dst).name}")
            except Exception as e:
                out.load_text(f"Error: {e}")
                self.set_status(str(e), ok=False)

    @on(Button.Pressed, "#btn-file-clr")
    def file_clear(self):
        self.query_one("#file-src", Input).value = ""
        self.query_one("#file-dst", Input).value = ""
        self.query_one("#file-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-sym")
    def do_symmetric(self):
        mode    = self.query_one("#sym-mode",   Select).value
        pp      = self.query_one("#sym-pass",   Input).value
        pp2     = self.query_one("#sym-pass2",  Input).value
        cipher  = self.query_one("#sym-cipher", Select).value
        text_in = self.query_one("#sym-in",     TextArea).text.strip()
        out     = self.query_one("#sym-out",    TextArea)

        if not text_in:
            return self.set_status("No input text.", ok=False)

        if mode == "enc":
            if not pp:
                return self.set_status("Passphrase required.", ok=False)
            if pp != pp2:
                return self.set_status("Passphrases don't match.", ok=False)
            r = gpg.encrypt(
                text_in, [], symmetric=True, passphrase=pp, armor=True,
                extra_args=["--cipher-algo", cipher],
            )
            if r.ok:
                out.load_text(str(r))
                self.set_status("Symmetric encryption OK.")
            else:
                out.load_text(f"ERROR:\n{r.stderr}")
                self.set_status(f"Symmetric encrypt failed: {r.status}", ok=False)

        elif mode == "dec":
            r = gpg.decrypt(text_in, passphrase=pp or None)
            if r.ok:
                out.load_text(str(r))
                self.set_status("Symmetric decryption OK.")
            else:
                out.load_text(f"ERROR:\n{r.stderr}")
                self.set_status(f"Symmetric decrypt failed: {r.status}", ok=False)

    @on(Button.Pressed, "#btn-ks-search")
    def do_ks_search(self):
        query = self.query_one("#ks-query", Input).value.strip()
        if not query:
            return self.set_status("Enter email or fingerprint to search.", ok=False)
        try:
            # Use keys.openpgp.org HTTPS REST API (port 443, not HKP port 11371)
            q = url_quote(query)
            url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{q}" \
                  if re.match(r'^[0-9A-Fa-f]{16,}$', query.replace(' ', '')) \
                  else f"https://keys.openpgp.org/search?q={q}"
            req = urllib.request.Request(url, headers={"Accept": "application/json, text/html"})
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read().decode()
            # Strip HTML tags for readability
            text = re.sub(r'<[^>]+>', '', body).strip()
            text = re.sub(r'\n{3,}', '\n\n', text)
            self.query_one("#ks-out", TextArea).load_text(text[:4000] or "(no results)")
            self.set_status("Keyserver search complete.")
        except Exception as e:
            self.query_one("#ks-out", TextArea).load_text(f"Error: {e}")
            self.set_status(str(e), ok=False)

    @on(Button.Pressed, "#btn-ks-fetch")
    def do_ks_fetch(self):
        query = self.query_one("#ks-query", Input).value.strip()
        if not query:
            return self.set_status("Enter fingerprint or email to fetch.", ok=False)
        try:
            # Use keys.openpgp.org HTTPS REST API
            q = url_quote(query.replace(' ', '').upper())
            if re.match(r'^[0-9A-Fa-f]{16,}$', query.replace(' ', '')):
                url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{q}"
            else:
                url = f"https://keys.openpgp.org/vks/v1/by-email/{url_quote(query)}"
            req = urllib.request.Request(url, headers={"Accept": "application/pgp-keys"})
            with urllib.request.urlopen(req, timeout=15) as r:
                armor = r.read().decode()
            if "BEGIN PGP" not in armor:
                self.query_one("#ks-out", TextArea).load_text(f"No key found for: {query}")
                return self.set_status("Key not found.", ok=False)
            result = gpg.import_keys(armor)
            msg = f"Imported: {result.imported}  Unchanged: {result.unchanged}  Errors: {result.not_imported}\n"
            if result.fingerprints:
                msg += "Fingerprints:\n" + "\n".join(result.fingerprints)
            self.query_one("#ks-out", TextArea).load_text(msg)
            if result.imported:
                self._refresh_all_key_selects()
                self.set_status(f"Key imported: {result.fingerprints[0][-16:] if result.fingerprints else ''}")
            else:
                self.set_status("Fetch failed — see output.", ok=False)
        except Exception as e:
            self.query_one("#ks-out", TextArea).load_text(f"Error: {e}")
            self.set_status(str(e), ok=False)

    @on(Button.Pressed, "#btn-keys-import")
    def do_keys_import(self):
        text = self.query_one("#keys-import-text", TextArea).text.strip()
        if not text:
            return self.set_status("Paste a key block to import.", ok=False)
        result = gpg.import_keys(text)
        msg = (
            f"Imported: {result.imported}  "
            f"Unchanged: {result.unchanged}  "
            f"Errors: {result.not_imported}\n"
        )
        if result.fingerprints:
            msg += "Fingerprints:\n" + "\n".join(result.fingerprints)
        self.query_one("#keys-import-out", TextArea).load_text(msg)
        self._refresh_all_key_selects()
        if result.imported:
            self.set_status(f"Imported {result.imported} key(s) — Encrypt/sign selects updated.")
        elif result.unchanged:
            self.set_status(f"Key already present ({result.unchanged} unchanged).", ok=False)
        else:
            self.set_status(f"Import failed — {result.not_imported} error(s).", ok=False)

    @on(Button.Pressed, "#btn-keys-export-pub")
    def do_keys_export_pub(self):
        fpr = self.query_one("#keys-export-id", Input).value.strip()
        if not fpr:
            return self.set_status("Enter fingerprint or email to export.", ok=False)
        armor = gpg.export_keys(fpr, armor=True)
        if armor:
            self.query_one("#keys-export-out", TextArea).load_text(armor)
            self.set_status(f"Exported public key: {fpr}")
        else:
            self.set_status(f"No public key found for: {fpr}", ok=False)

    @on(Button.Pressed, "#btn-keys-export-sec")
    def do_keys_export_sec(self):
        fpr = self.query_one("#keys-export-id", Input).value.strip()
        if not fpr:
            return self.set_status("Enter fingerprint or email to export.", ok=False)
        pp = self.query_one("#keys-export-pass", Input).value or None
        if pp is None:
            return self.set_status("Enter passphrase to export secret key (GnuPG 2.1+ requirement).", ok=False)
        armor = gpg.export_keys(fpr, secret=True, armor=True, passphrase=pp)
        if armor:
            self.query_one("#keys-export-out", TextArea).load_text(armor)
            self.set_status(f"Exported SECRET key: {fpr}  handle with care!")
        else:
            self.set_status(f"No secret key found for: {fpr} (wrong passphrase?)", ok=False)

    def _do_bundle_dump(self, mode: str):
        """Dump hybrid signing bundle. mode = 'pub' | 'priv' | 'full'"""
        pgp_id   = self.query_one("#bundle-dump-pgp-id",    Input).value.strip()
        mldsa_path = self.query_one("#bundle-dump-mldsa-path", Input).value.strip()
        pp       = self.query_one("#bundle-dump-pass",       Input).value or None
        out      = self.query_one("#bundle-dump-out", TextArea)

        if not pgp_id:
            return self.set_status("Enter PGP fingerprint or email.", ok=False)
        if not mldsa_path:
            return self.set_status("Enter path to ML-DSA-65 key file.", ok=False)

        # Read ML-DSA key file
        try:
            mldsa_text = Path(mldsa_path).expanduser().read_text().strip()
        except Exception as e:
            out.load_text(f"Cannot read ML-DSA-65 key file:\n{e}")
            return self.set_status(str(e), ok=False)

        # Extract public and private blocks from key file
        mldsa_pub = mldsa_priv = ""
        pub_m = re.search(
            r'(-----BEGIN ML-DSA-65 PUBLIC KEY-----.*?-----END ML-DSA-65 PUBLIC KEY-----)',
            mldsa_text, re.DOTALL)
        priv_m = re.search(
            r'(-----BEGIN ML-DSA-65 PRIVATE KEY-----.*?-----END ML-DSA-65 PRIVATE KEY-----)',
            mldsa_text, re.DOTALL)
        if pub_m:
            mldsa_pub = pub_m.group(1).strip()
        if priv_m:
            mldsa_priv = priv_m.group(1).strip()

        if mode in ("pub", "full") and not mldsa_pub:
            out.load_text("No -----BEGIN ML-DSA-65 PUBLIC KEY----- block found in file.")
            return self.set_status("ML-DSA-65 public key not found in file.", ok=False)
        if mode in ("priv", "full") and not mldsa_priv:
            out.load_text("No -----BEGIN ML-DSA-65 PRIVATE KEY----- block found in file.\nPrivate key is only present if you saved the full keygen output.")
            return self.set_status("ML-DSA-65 private key not found in file.", ok=False)

        # Export PGP keys
        pgp_pub = gpg.export_keys(pgp_id, armor=True)
        if not pgp_pub:
            out.load_text(f"No public key found for: {pgp_id}")
            return self.set_status(f"PGP key not found: {pgp_id}", ok=False)

        # Get fingerprint
        keys = gpg.list_keys(keys=pgp_id)
        fpr = keys[0]["fingerprint"] if keys else pgp_id
        uids = keys[0]["uids"][0] if keys and keys[0]["uids"] else pgp_id

        if mode == "pub":
            pub_bundle = (
                f"-----BEGIN PGP+ML-DSA-65 SIGNING KEY BUNDLE-----\n"
                f"PGP-Fingerprint: {fpr}\n"
                f"Identity: {uids}\n\n"
                f"{pgp_pub.strip()}\n\n"
                f"{mldsa_pub}\n"
                f"-----END PGP+ML-DSA-65 SIGNING KEY BUNDLE-----"
            )
            result = (
                f"=== PUBLIC BUNDLE (paste this into Deadman) ===\n\n"
                f"{pub_bundle}\n\n"
                f"=== PGP COMPONENT ===\n\n{pgp_pub}\n\n"
                f"=== ML-DSA-65 PUBLIC KEY ===\n\n{mldsa_pub}"
            )
            out.load_text(result)
            self.set_status("Public bundle dumped.")

        elif mode == "priv":
            if pp is None:
                out.load_text("Passphrase required for PGP secret key export.")
                return self.set_status("Enter passphrase for PGP secret key.", ok=False)
            pgp_sec = gpg.export_keys(pgp_id, secret=True, armor=True, passphrase=pp)
            if not pgp_sec:
                out.load_text(f"PGP secret key export failed for: {pgp_id} (wrong passphrase?)")
                return self.set_status("PGP secret key export failed.", ok=False)
            result = (
                f"=== PRIVATE COMPONENTS — DO NOT SHARE ===\n\n"
                f"PGP-Fingerprint: {fpr}\n"
                f"Identity: {uids}\n\n"
                f"--- PGP SECRET KEY ---\n\n{pgp_sec}\n\n"
                f"--- ML-DSA-65 PRIVATE KEY ---\n\n{mldsa_priv}"
            )
            out.load_text(result)
            self.set_status("Private bundle dumped — handle with care!")

        elif mode == "full":
            if pp is None:
                out.load_text("Passphrase required for PGP secret key export.")
                return self.set_status("Enter passphrase for PGP secret key.", ok=False)
            pgp_sec = gpg.export_keys(pgp_id, secret=True, armor=True, passphrase=pp)
            if not pgp_sec:
                out.load_text(f"PGP secret key export failed for: {pgp_id} (wrong passphrase?)")
                return self.set_status("PGP secret key export failed.", ok=False)
            pub_bundle = (
                f"-----BEGIN PGP+ML-DSA-65 SIGNING KEY BUNDLE-----\n"
                f"PGP-Fingerprint: {fpr}\n"
                f"Identity: {uids}\n\n"
                f"{pgp_pub.strip()}\n\n"
                f"{mldsa_pub}\n"
                f"-----END PGP+ML-DSA-65 SIGNING KEY BUNDLE-----"
            )
            result = (
                f"=== PUBLIC BUNDLE (paste into Deadman) ===\n\n"
                f"{pub_bundle}\n\n"
                f"{'='*60}\n"
                f"=== PGP PUBLIC KEY ===\n\n{pgp_pub}\n\n"
                f"=== ML-DSA-65 PUBLIC KEY ===\n\n{mldsa_pub}\n\n"
                f"{'='*60}\n"
                f"=== PRIVATE COMPONENTS — DO NOT SHARE ===\n\n"
                f"--- PGP SECRET KEY ---\n\n{pgp_sec}\n\n"
                f"--- ML-DSA-65 PRIVATE KEY ---\n\n{mldsa_priv}"
            )
            out.load_text(result)
            self.set_status("Full bundle dumped — CONTAINS PRIVATE KEYS.")

    @on(Button.Pressed, "#btn-bundle-pub")
    def do_bundle_pub(self):
        self._do_bundle_dump("pub")

    @on(Button.Pressed, "#btn-bundle-priv")
    def do_bundle_priv(self):
        self._do_bundle_dump("priv")

    @on(Button.Pressed, "#btn-bundle-full")
    def do_bundle_full(self):
        self._do_bundle_dump("full")


    @on(Button.Pressed, "#btn-enc-clr")
    def enc_clear(self):
        self.query_one("#enc-in",  TextArea).load_text("")
        self.query_one("#enc-out", TextArea).load_text("")
        self.query_one("#enc-pass", Input).value = ""
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-dec-clr")
    def dec_clear(self):
        self.query_one("#dec-in",  TextArea).load_text("")
        self.query_one("#dec-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-batch-clr")
    def batch_clear(self):
        self.query_one("#batch-in",  TextArea).load_text("")
        self.query_one("#batch-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-pqc-clr")
    def pqc_clear(self):
        self.query_one("#pqc-in",  TextArea).load_text("")
        self.query_one("#pqc-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-sv-clr")
    def sv_clear(self):
        self.query_one("#sv-in",  TextArea).load_text("")
        self.query_one("#sv-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-sym-clr")
    def sym_clear(self):
        self.query_one("#sym-in",  TextArea).load_text("")
        self.query_one("#sym-out", TextArea).load_text("")
        self.set_status("Cleared.")

    @on(Button.Pressed, "#btn-keys-refresh")
    def keys_refresh(self):
        self._refresh_all_key_selects()

    # -- Deadman Storage handlers ----------------------------------------------
    @on(Button.Pressed, "#btn-dm-gen")
    def dm_generate(self):
        entropy  = secrets.token_bytes(32)
        mnemonic = _dm_entropy_to_mnemonic(entropy)
        self.query_one("#dm-mnemonic", TextArea).load_text(mnemonic)
        self.query_one("#dm-out", TextArea).load_text(
            "Mnemonic generated.\n"
            "Write it down — it is never stored anywhere.\n"
            "Click 'Create Vault' to register it on the gateway."
        )
        self.set_status("Mnemonic generated.")

    @on(Button.Pressed, "#btn-dm-create")
    def dm_create(self):
        out      = self.query_one("#dm-out", TextArea)
        mnemonic = self.query_one("#dm-mnemonic", TextArea).text.strip()
        gateway  = self.query_one("#dm-gateway", Input).value.strip()
        proxy    = self.query_one("#dm-proxy", Input).value.strip()
        gpg_fp   = self.query_one("#dm-gpg-key", Select).value

        if not mnemonic:
            out.load_text("Generate a mnemonic first.")
            return self.set_status("No mnemonic.", ok=False)
        if not gpg_fp:
            out.load_text("Select a GPG key to register with the vault.")
            return self.set_status("No GPG key selected.", ok=False)

        try:
            dk       = _dm_derive(mnemonic)
            pgp_pub  = gpg.export_keys(gpg_fp, armor=True)
            if not pgp_pub:
                raise ValueError(f"Could not export GPG key: {gpg_fp}")

            out.load_text("Connecting via Tor… (may take 10–20s)")
            self.refresh()

            result = _dm_http_post(
                "/v1/vault/create",
                {"vault_id": dk["vault_id"],
                 "switch_verifier": dk["switch_verifier"],
                 "key_type": "pgp",
                 "pgp_pubkey": pgp_pub,
                 "mldsa_pubkey": ""},
                gateway, proxy,
            )

            if result.get("status") == "created":
                host = gateway.replace("http://", "").rstrip("/")
                panel_url = f"http://{host}/panel/"
                out.load_text(
                    f"✓ Vault created\n\n"
                    f"Vault ID:  {dk['vault_id']}\n"
                    f"Panel URL: {panel_url}\n\n"
                    f"Mnemonic is in the field above — write it down.\n"
                    f"GPG key:   {gpg_fp}\n\n"
                    f"To access: open {panel_url} in Tor Browser\n"
                    f"and enter your vault ID."
                )
                self.set_status("Vault created.")
            else:
                out.load_text(f"Gateway error:\n{json.dumps(result, indent=2)}")
                self.set_status("Vault creation failed.", ok=False)

        except Exception as exc:
            out.load_text(f"Error: {exc}")
            self.set_status(f"Error: {exc}", ok=False)

    @on(Button.Pressed, "#btn-dm-clr")
    def dm_clear(self):
        self.query_one("#dm-mnemonic", TextArea).load_text("")
        self.query_one("#dm-out",      TextArea).load_text("")
        self.set_status("Cleared.")


if __name__ == "__main__":
    PGPsus().run()