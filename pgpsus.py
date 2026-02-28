#!/usr/bin/env python3
"""PGPsus — PGP / Age / PQC Hybrid encryption TUI — Textual 8, GPG keyring auto-detected."""

VERSION = "1.1"
import gnupg, os, re, base64, json, subprocess, shutil
from pathlib import Path
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.theme import Theme
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane,
    TextArea, Select, SelectionList, Button, Label, Input, Static
)
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.events import Paste
from textual import on

import hybrid_crypto

def _clipboard_paste() -> str:
    """Read clipboard text using whatever tool is available."""
    import os
    env = os.environ.copy()
    # Ensure DISPLAY is set — required for X11 clipboard tools running as subprocesses
    if "DISPLAY" not in env:
        env["DISPLAY"] = ":0"

    for cmd in (
        ["wl-paste", "--no-newline"],
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["pbpaste"],
    ):
        if shutil.which(cmd[0]):
            try:
                return subprocess.check_output(cmd, timeout=2, env=env).decode()
            except Exception:
                pass
    # Tkinter fallback — works on any X11 system with python3-tk
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        text = root.clipboard_get()
        root.destroy()
        return text
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
    # Tkinter fallback
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.after(200, root.destroy)
        root.mainloop()
        return True
    except Exception:
        pass
    return False

# ── GPG setup ─────────────────────────────────────────────────────────────────
GPG_HOME = os.environ.get("GNUPGHOME", str(Path.home() / ".gnupg"))
gpg = gnupg.GPG(gnupghome=GPG_HOME)
gpg.encoding = "utf-8"

PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", re.DOTALL)
HYB_BLOCK_RE = re.compile(
    r"-----BEGIN HYBRID MESSAGE-----.*?-----END HYBRID MESSAGE-----", re.DOTALL)

def gpg_pub_keys():
    return [(k["uids"][0] if k["uids"] else k["keyid"], k["fingerprint"]) for k in gpg.list_keys()]

def gpg_sec_keys():
    return [(k["uids"][0] if k["uids"] else k["keyid"], k["fingerprint"]) for k in gpg.list_keys(True)]

# ── Themes ────────────────────────────────────────────────────────────────────
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
        primary="#4a9edd",   secondary="#a0c8f0",
        background="#ddeeff", surface="#eef6ff",
        panel="#c8e4f8",     foreground="#0a1a2e",
        success="#2a8abf", warning="#b07820", error="#c03030",
        dark=False,
    ),
    "infernal": Theme(
        name="infernal",
        primary="#dd4a1a",   secondary="#ff8c00",
        background="#0d0000", surface="#1a0500",
        panel="#2a0800",     foreground="#ffcc99",
        success="#cc6600", warning="#ff8c00", error="#ff2200",
        dark=True,
    ),
}

SWATCHES = {
    "dark":     ["#0d0d0d","#111111","#3a8a3a","#e8e8e8","#a8e8a8"],
    "light":    ["#f5f5f0","#ffffff","#1a7a1a","#1a1a1a","#1a4a1a"],
    "heavenly": ["#ddeeff","#eef6ff","#4a9edd","#0a1a2e","#2a8abf"],
    "infernal": ["#0d0000","#1a0500","#dd4a1a","#ffcc99","#cc6600"],
}
SWATCH_LABELS = ["bg","surface","primary","text","output"]

CSS = """
Screen { background: $background; color: $foreground; }

#theme-bar {
    height: 3;
    background: #1a1a1a;
    border-bottom: solid #333333;
    padding: 0 1;
    align: left middle;
}
#theme-bar.light {
    background: #e8e8e0;
    border-bottom: solid #cccccc;
}
#theme-bar.heavenly {
    background: #c8e4f8;
    border-bottom: solid #7ab8e8;
}
#theme-bar.infernal {
    background: #2a0800;
    border-bottom: solid #8b2000;
}
#theme-bar Label { color: #888888; margin-right: 1; }
#theme-bar.light Label { color: #555555; }
#theme-bar.heavenly Label { color: #1a4a6a; }
#theme-btn-dark     { min-width: 10; background: #3a8a3a; color: #ffffff; border: none; margin-right: 1; }
#theme-btn-light    { min-width: 10; background: #2a2a2a; color: #aaaaaa; border: none; margin-right: 1; }
#theme-btn-heavenly { min-width: 12; background: #4a9edd; color: #ffffff; border: none; margin-right: 1; }
#theme-btn-infernal { min-width: 12; background: #dd4a1a; color: #ffcc99; border: none; margin-right: 1; }
#theme-btn-dark:hover     { background: #4a9a4a; }
#theme-btn-light:hover    { background: #3a3a3a; }
#theme-btn-heavenly:hover { background: #5ab0ef; }
#theme-btn-infernal:hover { background: #ee5a2a; }
.swatch { width: 3; height: 1; margin: 0 0 0 1; }

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
.merged-pane { height: 1fr; }
.mode-bar { height: 3; padding: 0 1; align: left middle; }
.tab-section { height: 1fr; }
.tab-section.hidden { display: none; }
"""

class PGPsus(App):
    CSS = CSS
    TITLE = f"PGPsus v{VERSION}"
    BINDINGS = [
        ("ctrl+q", "quit",            "Quit"),
        ("ctrl+e", "tab('tab-enc')",  "Encrypt"),
        ("ctrl+d", "tab('tab-dec')",  "Decrypt"),
        ("ctrl+s", "tab('tab-sign')", "Sign"),
        ("ctrl+k", "tab('tab-keys')", "Keys"),
        ("ctrl+f", "tab('tab-file')", "File"),
        Binding("ctrl+v",       "paste", "Paste", priority=True),
        Binding("ctrl+shift+v", "paste", "Paste", priority=True),
        Binding("f2",           "paste", "Paste", priority=True),
        Binding("ctrl+c",       "copy",  "Copy",  priority=True),
        Binding("ctrl+y",       "copy",  "Copy",  priority=True),
        Binding("f3",           "copy",  "Copy",  priority=True),
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

    def on_paste(self, event: Paste) -> None:
        """Handle terminal bracketed paste. Falls back to xclip if text empty (Whonix safe-paste dialog strips it)."""
        event.stop()
        text = event.text if event.text else _clipboard_paste()
        self._insert_text(text)

    def action_paste(self) -> None:
        """Ctrl+V / Ctrl+Shift+V: read from system clipboard and insert into focused widget."""
        import os
        text = _clipboard_paste()
        # Diagnostic notification — shows exactly what happened so paste issues can be traced
        focused_type = type(self.focused).__name__
        display = os.environ.get("DISPLAY", "unset")
        if text:
            self._insert_text(text)
            self.notify(f"Pasted {len(text)} chars into {focused_type}", timeout=2)
        else:
            self.notify(
                f"Clipboard empty — DISPLAY={display}, focused={focused_type}. "
                f"Run: xclip -selection clipboard -o",
                severity="warning", timeout=6
            )

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
        yield Header(show_clock=True)
        with Horizontal(id="theme-bar"):
            yield Label("Theme:")
            yield Button("🌑 Dark",    id="theme-btn-dark")
            yield Button("☀️  Light",  id="theme-btn-light")
            yield Button("☁️  Heavenly", id="theme-btn-heavenly")
            yield Button("🔥 Infernal",  id="theme-btn-infernal")
            for i, (color, lbl) in enumerate(zip(SWATCHES["dark"], SWATCH_LABELS)):
                yield Static(" ", id=f"sw{i}", classes="swatch")
        with TabbedContent(id="tabs"):
            with TabPane("🔒 Encrypt",     id="tab-enc"):  yield self._enc_merged_pane()
            with TabPane("🔓 Decrypt",     id="tab-dec"):  yield self._dec_merged_pane()
            with TabPane("✍️ Sign/Verify", id="tab-sign"): yield self._sign_verify_pane()
            with TabPane("🗝 Keys",        id="tab-keys"): yield self._keys_merged_pane()
            with TabPane("📁 File",        id="tab-file"): yield self._file_pane()
        yield Label("Ready", id="status-bar")
        yield Footer()

    def on_mount(self):
        for name, theme in THEMES.items():
            self.register_theme(theme)
        self.theme = "dark"
        self._apply_swatches("dark")

    # ── Theme bar ─────────────────────────────────────────────────────────────
    def _apply_swatches(self, theme_name: str):
        colors = SWATCHES[theme_name]
        labels = SWATCH_LABELS
        for i, (color, lbl) in enumerate(zip(colors, labels)):
            sw = self.query_one(f"#sw{i}", Static)
            sw.styles.background = color
            sw.tooltip = lbl

    @on(Button.Pressed, "#theme-btn-dark")
    def theme_dark(self):
        self.theme = "dark"
        self._apply_swatches("dark")
        bar = self.query_one("#theme-bar")
        bar.remove_class("light"); bar.remove_class("heavenly"); bar.remove_class("infernal")
        self.query_one("#theme-btn-dark").styles.background     = "#3a8a3a"
        self.query_one("#theme-btn-dark").styles.color          = "#ffffff"
        self.query_one("#theme-btn-light").styles.background    = "#2a2a2a"
        self.query_one("#theme-btn-light").styles.color         = "#aaaaaa"
        self.query_one("#theme-btn-heavenly").styles.background = "#4a9edd"
        self.query_one("#theme-btn-heavenly").styles.color      = "#ffffff"
        self.query_one("#theme-btn-infernal").styles.background = "#dd4a1a"
        self.query_one("#theme-btn-infernal").styles.color      = "#ffcc99"
        self.set_status("Theme: dark")

    @on(Button.Pressed, "#theme-btn-light")
    def theme_light(self):
        self.theme = "light"
        self._apply_swatches("light")
        bar = self.query_one("#theme-bar")
        bar.remove_class("heavenly"); bar.remove_class("infernal"); bar.add_class("light")
        self.query_one("#theme-btn-light").styles.background    = "#3a8a3a"
        self.query_one("#theme-btn-light").styles.color         = "#ffffff"
        self.query_one("#theme-btn-dark").styles.background     = "#2a2a2a"
        self.query_one("#theme-btn-dark").styles.color          = "#aaaaaa"
        self.query_one("#theme-btn-heavenly").styles.background = "#4a9edd"
        self.query_one("#theme-btn-heavenly").styles.color      = "#ffffff"
        self.query_one("#theme-btn-infernal").styles.background = "#dd4a1a"
        self.query_one("#theme-btn-infernal").styles.color      = "#ffcc99"
        self.set_status("Theme: light")

    @on(Button.Pressed, "#theme-btn-heavenly")
    def theme_heavenly(self):
        self.theme = "heavenly"
        self._apply_swatches("heavenly")
        bar = self.query_one("#theme-bar")
        bar.remove_class("light"); bar.remove_class("infernal"); bar.add_class("heavenly")
        self.query_one("#theme-btn-heavenly").styles.background = "#2a6a9a"
        self.query_one("#theme-btn-heavenly").styles.color      = "#ffffff"
        self.query_one("#theme-btn-dark").styles.background     = "#2a2a2a"
        self.query_one("#theme-btn-dark").styles.color          = "#aaaaaa"
        self.query_one("#theme-btn-light").styles.background    = "#a0c0d8"
        self.query_one("#theme-btn-light").styles.color         = "#1a1a1a"
        self.query_one("#theme-btn-infernal").styles.background = "#dd4a1a"
        self.query_one("#theme-btn-infernal").styles.color      = "#ffcc99"
        self.set_status("Theme: heavenly")

    @on(Button.Pressed, "#theme-btn-infernal")
    def theme_infernal(self):
        self.theme = "infernal"
        self._apply_swatches("infernal")
        bar = self.query_one("#theme-bar")
        bar.remove_class("light"); bar.remove_class("heavenly"); bar.add_class("infernal")
        self.query_one("#theme-btn-infernal").styles.background = "#8b2000"
        self.query_one("#theme-btn-infernal").styles.color      = "#ffcc99"
        self.query_one("#theme-btn-dark").styles.background     = "#1a0500"
        self.query_one("#theme-btn-dark").styles.color          = "#884433"
        self.query_one("#theme-btn-light").styles.background    = "#1a0500"
        self.query_one("#theme-btn-light").styles.color         = "#884433"
        self.query_one("#theme-btn-heavenly").styles.background = "#1a0500"
        self.query_one("#theme-btn-heavenly").styles.color      = "#884433"
        self.set_status("Theme: infernal")

    # ── PGP Encrypt pane ──────────────────────────────────────────────────────
    def _enc_pane(self):
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        return Horizontal(
            Vertical(
                Label("Recipients (multi-select):"),
                SelectionList(*pub_opts, id="enc-recipient"),
                Label("Sign with (optional):"),
                Select([("(none)","")] + [(uid,fp) for uid,fp in sec], id="enc-signer", allow_blank=False),
                Label("Passphrase (signing):"), Input(password=True, id="enc-pass"),
                Button("🔒 Encrypt", id="btn-enc", variant="success"),
                Button("🗑 Clear",   id="btn-enc-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Plaintext:", classes="section-label"), TextArea("", id="enc-in"),
                Label("Ciphertext:", classes="section-label"), TextArea("", id="enc-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── PGP Decrypt pane ──────────────────────────────────────────────────────
    def _dec_pane(self):
        sec = gpg_sec_keys()
        return Horizontal(
            Vertical(
                Label("Key (auto-detect):"),
                Select([("(auto)","")] + [(uid,fp) for uid,fp in sec], id="dec-key", allow_blank=False),
                Label("Passphrase:"), Input(password=True, id="dec-pass"),
                Button("🔓 Decrypt", id="btn-dec", variant="success"),
                Button("🗑 Clear",   id="btn-dec-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Ciphertext (paste):", classes="section-label"), TextArea("", id="dec-in"),
                Label("Plaintext:", classes="section-label"), TextArea("", id="dec-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── Batch Decrypt pane ────────────────────────────────────────────────────
    def _batch_pane(self):
        return Horizontal(
            Vertical(
                Label("Passphrase (GPG):"), Input(password=True, id="batch-pass"),
                Label("PQC key file (optional):"), Input(placeholder="/path/to/priv.key", id="batch-pqc-key"),
                Label("Separator:"), Input(value="─"*20, id="batch-sep"),
                Button("📦 Decrypt All", id="btn-batch", variant="success"),
                Button("🗑 Clear",       id="btn-batch-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Paste PGP/PQC blocks here:", classes="section-label"), TextArea("", id="batch-in"),
                Label("Results:", classes="section-label"), TextArea("", id="batch-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── Key Generation pane ───────────────────────────────────────────────────
    def _keygen_pane(self):
        return Horizontal(
            Vertical(
                Label("Key type:"),
                Select([
                    ("Ed25519 (recommended)", "ed25519"),
                    ("RSA 4096",              "rsa4096"),
                    ("RSA 2048",              "rsa2048"),
                    ("PQC Hybrid (X25519+ML-KEM-768)", "pqc"),
                ], id="kg-type", allow_blank=False, value="ed25519"),
                Label("Real name:"),    Input(placeholder="Alice", id="kg-name"),
                Label("Email:"),        Input(placeholder="alice@example.com", id="kg-email"),
                Label("Passphrase:"),   Input(password=True, id="kg-pass"),
                Label("Confirm pass:"), Input(password=True, id="kg-pass2"),
                Label("Expires (GPG):"),
                Select([
                    ("Never", "0"),
                    ("1 year", "1y"),
                    ("2 years","2y"),
                    ("6 months","6m"),
                ], id="kg-expire", allow_blank=False, value="0"),
                Button("🔑 Generate", id="btn-kg", variant="success"),
                id="sidebar",
            ),
            Vertical(
                Label("Output:", classes="section-label"),
                TextArea("", id="kg-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── PQC Hybrid pane ───────────────────────────────────────────────────────
    def _pqc_pane(self):
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("Encrypt", "enc"),
                    ("Decrypt", "dec"),
                    ("Generate keypair", "gen"),
                ], id="pqc-mode", allow_blank=False, value="enc"),
                Label("Public key (encrypt):"),  TextArea("", id="pqc-pub-key"),
                Label("Private key (decrypt):"), Input(placeholder="/path/or/paste below", id="pqc-priv-path"),
                TextArea("", id="pqc-priv-key"),
                Button("🛡 Run", id="btn-pqc", variant="success"),
                Button("🗑 Clear", id="btn-pqc-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Input:", classes="section-label"), TextArea("", id="pqc-in"),
                Label("Output:", classes="section-label"), TextArea("", id="pqc-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── Sign / Verify pane ────────────────────────────────────────────────────
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
                Select([("(auto)","")] + [(uid,fp) for uid,fp in sec], id="sv-key", allow_blank=False),
                Label("Passphrase:"), Input(password=True, id="sv-pass"),
                Button("✍️ Run",  id="btn-sv",     variant="success"),
                Button("🗑 Clear", id="btn-sv-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Input:", classes="section-label"), TextArea("", id="sv-in"),
                Label("Output:", classes="section-label"), TextArea("", id="sv-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── File encrypt/decrypt pane ─────────────────────────────────────────────
    def _file_pane(self):
        pub = gpg_pub_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("GPG Encrypt", "gpg-enc"),
                    ("GPG Decrypt", "gpg-dec"),
                    ("PQC Encrypt", "pqc-enc"),
                    ("PQC Decrypt", "pqc-dec"),
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
                Button("📁 Run", id="btn-file", variant="success"),
                id="sidebar",
            ),
            Vertical(
                Label("Status/Output:", classes="section-label"),
                TextArea("", id="file-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── Symmetric encryption pane ─────────────────────────────────────────────
    def _sym_pane(self):
        return Horizontal(
            Vertical(
                Label("Mode:"),
                Select([
                    ("Encrypt", "enc"),
                    ("Decrypt", "dec"),
                ], id="sym-mode", allow_blank=False, value="enc"),
                Label("Passphrase:"),  Input(password=True, id="sym-pass"),
                Label("Confirm pass:"), Input(password=True, id="sym-pass2"),
                Label("Cipher:"),
                Select([
                    ("AES-256 (default)", "AES256"),
                    ("Camellia-256",      "CAMELLIA256"),
                    ("Twofish",           "TWOFISH"),
                ], id="sym-cipher", allow_blank=False, value="AES256"),
                Button("🔐 Run",   id="btn-sym",     variant="success"),
                Button("🗑 Clear", id="btn-sym-clr", variant="default"),
                id="sidebar",
            ),
            Vertical(
                Label("Input:", classes="section-label"), TextArea("", id="sym-in"),
                Label("Output:", classes="section-label"), TextArea("", id="sym-out", classes="output-area", read_only=True),
                id="main-area",
            ),
        )

    # ── Keys pane ─────────────────────────────────────────────────────────────
    def _keys_pane(self):
        return VerticalScroll(
            # Live key search
            Label("Filter keyring:", classes="section-label"),
            Input(placeholder="name, email or fingerprint…", id="keys-filter"),
            TextArea(self._keys_text(), id="keys-text", read_only=True),
            Button("🔄 Refresh", id="btn-keys-refresh", variant="default"),
            # Keyserver lookup
            Label("Keyserver lookup:", classes="section-label"),
            Input(placeholder="email or fingerprint", id="ks-query"),
            Button("🔍 Search",        id="btn-ks-search", variant="default"),
            Button("📥 Fetch & Import", id="btn-ks-fetch",  variant="success"),
            TextArea("", id="ks-out", read_only=True),
            # Import
            Label("Import key (paste block):", classes="section-label"),
            TextArea("", id="keys-import-text"),
            Button("📥 Import", id="btn-keys-import", variant="success"),
            # Export
            Label("Export key:", classes="section-label"),
            Input(placeholder="fingerprint or email", id="keys-export-id"),
            Button("📤 Export Public", id="btn-keys-export-pub", variant="default"),
            Button("📤 Export Secret", id="btn-keys-export-sec", variant="warning"),
            TextArea("", id="keys-export-out", read_only=True),
        )

    def _keys_text(self, query: str = "") -> str:
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        q = query.lower().strip()
        def matches(uid, fp):
            return not q or q in uid.lower() or q in fp.lower()
        lines = ["GPG PUBLIC KEYS", "="*50]
        matched = [(uid, fp) for uid, fp in pub if matches(uid, fp)]
        for uid, fp in matched:
            lines += [f"  {uid}", f"  {fp}", ""]
        if not matched:
            lines += [f"  (no public keys match '{q}')" if q else "  (none)", ""]
        lines += ["", "GPG SECRET KEYS", "="*50]
        matched_sec = [(uid, fp) for uid, fp in sec if matches(uid, fp)]
        for uid, fp in matched_sec:
            lines += [f"  {uid}", f"  {fp}", ""]
        if not matched_sec:
            lines += [f"  (no secret keys match '{q}')" if q else "  (none)", ""]
        lines += [f"\nGPG home: {GPG_HOME}"]
        return "\n".join(lines)

    # ── Merged pane: Encrypt (PGP + PQC) ─────────────────────────────────────
    def _enc_merged_pane(self):
        pub = gpg_pub_keys()
        sec = gpg_sec_keys()
        pub_opts = [(uid, fp) for uid, fp in pub] if pub else [("(no keys)", "")]
        return Vertical(
            Horizontal(
                Label("Mode:"),
                Select([("PGP Encrypt", "pgp"), ("PQC Hybrid", "pqc")],
                       id="enc-mode", allow_blank=False, value="pgp"),
                classes="mode-bar",
            ),
            Horizontal(
                Vertical(
                    Label("Recipients (multi-select):"),
                    Input(placeholder="filter recipients…", id="enc-recipient-filter"),
                    SelectionList(*pub_opts, id="enc-recipient"),
                    Label("Sign with (optional):"),
                    Select([("(none)", "")] + [(uid, fp) for uid, fp in sec],
                           id="enc-signer", allow_blank=False),
                    Label("Passphrase (signing):"), Input(password=True, id="enc-pass"),
                    Button("🔒 Encrypt", id="btn-enc",     variant="success"),
                    Button("🗑 Clear",   id="btn-enc-clr", variant="default"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Plaintext:",   classes="section-label"), TextArea("", id="enc-in"),
                    Label("Ciphertext:", classes="section-label"),
                    TextArea("", id="enc-out", classes="output-area", read_only=True),
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
                    Label("Public key (encrypt):"),  TextArea("", id="pqc-pub-key"),
                    Label("Private key (decrypt):"),
                    Input(placeholder="/path/or/paste below", id="pqc-priv-path"),
                    TextArea("", id="pqc-priv-key"),
                    Button("🛡 Run",   id="btn-pqc",     variant="success"),
                    Button("🗑 Clear", id="btn-pqc-clr", variant="default"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Input:",  classes="section-label"), TextArea("", id="pqc-in"),
                    Label("Output:", classes="section-label"),
                    TextArea("", id="pqc-out", classes="output-area", read_only=True),
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

    # ── Merged pane: Decrypt (PGP + Batch + Symmetric) ───────────────────────
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
                    Button("🔓 Decrypt", id="btn-dec",     variant="success"),
                    Button("🗑 Clear",   id="btn-dec-clr", variant="default"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Ciphertext (paste):", classes="section-label"),
                    TextArea("", id="dec-in"),
                    Label("Plaintext:", classes="section-label"),
                    TextArea("", id="dec-out", classes="output-area", read_only=True),
                    id="main-area",
                ),
                id="dec-section-pgp", classes="tab-section",
            ),
            Horizontal(
                Vertical(
                    Label("Passphrase (GPG):"), Input(password=True, id="batch-pass"),
                    Label("PQC key file (optional):"),
                    Input(placeholder="/path/to/priv.key", id="batch-pqc-key"),
                    Label("Separator:"), Input(value="─"*20, id="batch-sep"),
                    Button("📦 Decrypt All", id="btn-batch",     variant="success"),
                    Button("🗑 Clear",       id="btn-batch-clr", variant="default"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Paste PGP/PQC blocks here:", classes="section-label"),
                    TextArea("", id="batch-in"),
                    Label("Results:", classes="section-label"),
                    TextArea("", id="batch-out", classes="output-area", read_only=True),
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
                    Button("🔐 Run",   id="btn-sym",     variant="success"),
                    Button("🗑 Clear", id="btn-sym-clr", variant="default"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Input:",  classes="section-label"), TextArea("", id="sym-in"),
                    Label("Output:", classes="section-label"),
                    TextArea("", id="sym-out", classes="output-area", read_only=True),
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

    # ── Merged pane: Keys (Key List + Generate) ───────────────────────────────
    def _keys_merged_pane(self):
        return Vertical(
            Horizontal(
                Label("Mode:"),
                Select([("Key List", "list"), ("Generate Key", "gen")],
                       id="keys-mode", allow_blank=False, value="list"),
                classes="mode-bar",
            ),
            VerticalScroll(
                TextArea(self._keys_text(), id="keys-text", read_only=True),
                Button("🔄 Refresh", id="btn-keys-refresh", variant="default"),
                Label("Keyserver lookup:", classes="section-label"),
                Input(placeholder="email or fingerprint", id="ks-query"),
                Button("🔍 Search",         id="btn-ks-search", variant="default"),
                Button("📥 Fetch & Import", id="btn-ks-fetch",  variant="success"),
                TextArea("", id="ks-out", read_only=True),
                Label("Import key (paste block):", classes="section-label"),
                TextArea("", id="keys-import-text"),
                Button("📥 Import", id="btn-keys-import", variant="success"),
                Label("Export key:", classes="section-label"),
                Input(placeholder="fingerprint or email", id="keys-export-id"),
                Button("📤 Export Public", id="btn-keys-export-pub", variant="default"),
                Button("📤 Export Secret", id="btn-keys-export-sec", variant="warning"),
                TextArea("", id="keys-export-out", read_only=True),
                id="keys-section-list", classes="tab-section",
            ),
            Horizontal(
                Vertical(
                    Label("Key type:"),
                    Select([
                        ("Ed25519 (recommended)",          "ed25519"),
                        ("RSA 4096",                       "rsa4096"),
                        ("RSA 2048",                       "rsa2048"),
                        ("PQC Hybrid (X25519+ML-KEM-768)", "pqc"),
                    ], id="kg-type", allow_blank=False, value="ed25519"),
                    Label("Real name:"),    Input(placeholder="Alice", id="kg-name"),
                    Label("Email:"),        Input(placeholder="alice@example.com", id="kg-email"),
                    Label("Passphrase:"),   Input(password=True, id="kg-pass"),
                    Label("Confirm pass:"), Input(password=True, id="kg-pass2"),
                    Label("Expires (GPG):"),
                    Select([
                        ("Never",    "0"),
                        ("1 year",   "1y"),
                        ("2 years",  "2y"),
                        ("6 months", "6m"),
                    ], id="kg-expire", allow_blank=False, value="0"),
                    Button("🔑 Generate", id="btn-kg", variant="success"),
                    id="sidebar",
                ),
                Vertical(
                    Label("Output:", classes="section-label"),
                    TextArea("", id="kg-out", classes="output-area", read_only=True),
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

    # ── Helpers ───────────────────────────────────────────────────────────────
    def set_status(self, msg: str, ok: bool = True):
        bar = self.query_one("#status-bar", Label)
        bar.update(msg)
        bar.remove_class("status-ok", "status-err")
        bar.add_class("status-ok" if ok else "status-err")

    def action_tab(self, tab_id: str):
        self.query_one("#tabs", TabbedContent).active = tab_id

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
            ("#enc-signer",  sec_opts),
            ("#dec-key",     sec_auto),
            ("#sv-key",      sec_auto),
            ("#file-key",    pub_opts),
        ]:
            try:
                self.query_one(widget_id, Select).set_options(opts)
            except Exception:
                pass

        try:
            self.query_one("#keys-text", TextArea).load_text(self._keys_text())
        except Exception:
            pass

        self.set_status("Keys refreshed.")

    # ── Button handlers ───────────────────────────────────────────────────────
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
            self.set_status(f"Encrypted OK — {r.status}")
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
            self.set_status(f"Decrypted OK — signed by: {r.username or 'unsigned'}")
        else:
            self.query_one("#dec-out", TextArea).load_text(f"ERROR:\n{r.stderr}")
            self.set_status(f"Decrypt failed: {r.status}", ok=False)

    @on(Button.Pressed, "#btn-batch")
    def do_batch(self):
        raw = self.query_one("#batch-in", TextArea).text
        pp  = self.query_one("#batch-pass", Input).value
        sep = self.query_one("#batch-sep", Input).value
        pqc_priv_path = self.query_one("#batch-pqc-key", Input).value.strip()

        pqc_priv = None
        if pqc_priv_path:
            try:
                pqc_priv = hybrid_crypto.parse_private_key(Path(pqc_priv_path).read_text())
            except Exception as e:
                self.set_status(f"PQC key load failed: {e}", ok=False)

        pgp_blocks = PGP_BLOCK_RE.findall(raw)
        hyb_blocks = HYB_BLOCK_RE.findall(raw)
        total = len(pgp_blocks) + len(hyb_blocks)
        if not total:
            return self.set_status("No PGP or PQC blocks found.", ok=False)

        results = []
        ok_count = 0

        for i, block in enumerate(pgp_blocks, 1):
            r = gpg.decrypt(block, passphrase=pp or None, always_trust=True)
            if r.ok:
                ok_count += 1
                results.append(f"[GPG {i}/{len(pgp_blocks)}] ✓ {r.username or 'unsigned'}\n{str(r)}")
            else:
                results.append(f"[GPG {i}/{len(pgp_blocks)}] ✗ {r.status}\n{r.stderr.strip()}")

        for i, block in enumerate(hyb_blocks, 1):
            if not pqc_priv:
                results.append(f"[PQC {i}/{len(hyb_blocks)}] ✗ No PQC private key provided")
                continue
            try:
                pt = hybrid_crypto.decrypt(block, pqc_priv)
                ok_count += 1
                results.append(f"[PQC {i}/{len(hyb_blocks)}] ✓\n{pt}")
            except Exception as e:
                results.append(f"[PQC {i}/{len(hyb_blocks)}] ✗ {e}")

        self.query_one("#batch-out", TextArea).load_text(f"\n{sep}\n".join(results))
        self.set_status(f"Batch: {ok_count}/{total} decrypted OK")

    @on(Button.Pressed, "#btn-kg")
    def do_keygen(self):
        ktype  = self.query_one("#kg-type",   Select).value
        name   = self.query_one("#kg-name",   Input).value.strip()
        email  = self.query_one("#kg-email",  Input).value.strip()
        pp     = self.query_one("#kg-pass",   Input).value
        pp2    = self.query_one("#kg-pass2",  Input).value
        expire = self.query_one("#kg-expire", Select).value

        if not name or not email:
            return self.set_status("Name and email required.", ok=False)
        if pp != pp2:
            return self.set_status("Passphrases don't match.", ok=False)

        out = self.query_one("#kg-out", TextArea)

        if ktype == "pqc":
            try:
                pub, priv = hybrid_crypto.generate_keypair()
                pub_arm  = hybrid_crypto.armor_public_key(pub)
                priv_arm = hybrid_crypto.armor_private_key(priv)
                result = (
                    f"PQC Hybrid Key (X25519 + ML-KEM-768)\n"
                    f"Identity: {name} <{email}>\n"
                    f"{'='*50}\n\n"
                    f"{pub_arm}\n\n"
                    f"{'='*50}\n"
                    f"PRIVATE KEY — KEEP SECRET:\n\n"
                    f"{priv_arm}"
                )
                out.load_text(result)
                self.set_status("PQC keypair generated. Save private key securely!")
            except Exception as e:
                out.load_text(f"ERROR: {e}")
                self.set_status(f"PQC keygen failed: {e}", ok=False)
            return

        # GPG key
        key_map = {"ed25519": ("EDDSA",""), "rsa4096": ("RSA","4096"), "rsa2048": ("RSA","2048")}
        key_type, key_len = key_map[ktype]
        inp_kw = dict(
            key_type=key_type, name_real=name, name_email=email,
            expire_date=expire, passphrase=pp or None,
        )
        if key_len:
            inp_kw["key_length"] = int(key_len)

        inp = gpg.gen_key_input(**inp_kw)
        self.set_status("Generating key… (may take a moment)")
        key = gpg.gen_key(inp)
        if key.fingerprint:
            out.load_text(
                f"GPG key generated!\n"
                f"Type:        {ktype}\n"
                f"Identity:    {name} <{email}>\n"
                f"Fingerprint: {key.fingerprint}\n"
                f"Expires:     {expire if expire != '0' else 'never'}\n\n"
                f"Export public key:\n  gpg --armor --export {key.fingerprint}\n\n"
                f"Export private key (KEEP SECRET):\n  gpg --armor --export-secret-keys {key.fingerprint}"
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
                    f"{'='*50}\nPRIVATE KEY — KEEP SECRET:\n\n"
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
                pub = hybrid_crypto.parse_public_key(pub_text)
                ct  = hybrid_crypto.encrypt(inp, pub)
                out.load_text(ct)
                self.set_status("PQC encrypted OK.")
            except Exception as e:
                self.set_status(f"PQC encrypt error: {e}", ok=False)

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
                self.set_status(f"Signed OK — {result.status}")
            else:
                out.load_text(f"Signing failed.\nStatus: {result.status}\nStderr: {result.stderr}")
                self.set_status(f"Sign failed: {result.status}", ok=False)

        elif mode == "verify":
            result = gpg.verify(text)
            if result.valid:
                import datetime
                ts = ""
                try:
                    ts = datetime.datetime.fromtimestamp(float(result.timestamp)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    ts = str(result.timestamp)
                out.load_text(
                    f"✓ VALID signature\n"
                    f"User:      {result.username}\n"
                    f"Key ID:    {result.key_id}\n"
                    f"Timestamp: {ts}\n"
                    f"Status:    {result.status}"
                )
                self.set_status("Signature valid.")
            else:
                out.load_text(
                    f"✗ INVALID / unverified\n"
                    f"Status: {result.status}\n"
                    f"Key ID: {result.key_id or '(unknown)'}"
                )
                self.set_status("Signature invalid or not found.", ok=False)

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
                    out.load_text(f"✓ Encrypted to: {dst}\n{r.stdout}")
                    self.set_status(f"GPG file encrypted → {Path(dst).name}")
                else:
                    out.load_text(f"✗ GPG error:\n{r.stderr}")
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
                    out.load_text(f"✓ Decrypted to: {dst}\n{r.stdout}")
                    self.set_status(f"GPG file decrypted → {Path(dst).name}")
                else:
                    out.load_text(f"✗ GPG error:\n{r.stderr}")
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
                pub = hybrid_crypto.parse_public_key(pub_text)
                data = Path(src).read_bytes()
                b64_data = base64.b64encode(data).decode("utf-8")
                ct = hybrid_crypto.encrypt(b64_data, pub)
                Path(dst).write_text(ct)
                out.load_text(f"✓ PQC encrypted to: {dst}")
                self.set_status(f"PQC file encrypted → {Path(dst).name}")
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
                out.load_text(f"✓ PQC decrypted to: {dst}")
                self.set_status(f"PQC file decrypted → {Path(dst).name}")
            except Exception as e:
                out.load_text(f"Error: {e}")
                self.set_status(str(e), ok=False)

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
                text_in, symmetric=True, passphrase=pp, armor=True,
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
            r = subprocess.run(
                ["gpg", "--keyserver", "keys.openpgp.org",
                 "--search-keys", query],
                capture_output=True, text=True, timeout=30
            )
            output = (r.stdout + r.stderr).strip() or "(no output)"
            self.query_one("#ks-out", TextArea).load_text(output)
            self.set_status("Keyserver search complete.")
        except Exception as e:
            self.query_one("#ks-out", TextArea).load_text(f"Error: {e}")
            self.set_status(str(e), ok=False)

    @on(Button.Pressed, "#btn-ks-fetch")
    def do_ks_fetch(self):
        query = self.query_one("#ks-query", Input).value.strip()
        if not query:
            return self.set_status("Enter fingerprint or key ID to fetch.", ok=False)
        try:
            r = subprocess.run(
                ["gpg", "--keyserver", "keys.openpgp.org",
                 "--recv-keys", query],
                capture_output=True, text=True, timeout=30
            )
            output = (r.stdout + r.stderr).strip() or "(no output)"
            self.query_one("#ks-out", TextArea).load_text(output)
            if r.returncode == 0:
                self._refresh_all_key_selects()
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
        self.query_one("#keys-export-out", TextArea).load_text(msg)
        self._refresh_all_key_selects()
        self.set_status(f"Import: {result.imported} key(s) imported.")

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
        armor = gpg.export_keys(fpr, secret=True, armor=True)
        if armor:
            self.query_one("#keys-export-out", TextArea).load_text(armor)
            self.set_status(f"Exported SECRET key: {fpr} — handle with care!")
        else:
            self.set_status(f"No secret key found for: {fpr}", ok=False)

    @on(Button.Pressed, "#btn-enc-clr")
    def enc_clear(self):
        self.query_one("#enc-in",  TextArea).load_text("")
        self.query_one("#enc-out", TextArea).load_text("")
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

    @on(Input.Changed, "#keys-filter")
    def keys_filter_changed(self, event: Input.Changed) -> None:
        """Live-filter the keyring display as the user types."""
        for ta in self.query("#keys-text"):
            ta.load_text(self._keys_text(event.value))

    def _filter_selection_list(self, list_id: str, query: str) -> None:
        """Rebuild a SelectionList to show only keys matching query."""
        pub = gpg_pub_keys()
        q = query.lower().strip()
        filtered = [(uid, fp) for uid, fp in pub if not q or q in uid.lower() or q in fp.lower()]
        try:
            sl = self.query_one(f"#{list_id}", SelectionList)
            sl.clear_options()
            for uid, fp in filtered:
                sl.add_option((uid, fp))
            if not filtered:
                sl.add_option((f"(no keys match '{q}')" if q else "(no keys)", ""))
        except Exception:
            pass

    @on(Input.Changed, "#enc-recipient-filter")
    def enc_recipient_filter(self, event: Input.Changed) -> None:
        self._filter_selection_list("enc-recipient", event.value)


if __name__ == "__main__":
    PGPsus().run()
