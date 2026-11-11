#!/usr/bin/env python3
"""Desktop packet viewer for the Netwatch capture engine."""
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import font as tkfont, ttk

from model import (CaptureModel, JsonLines, default_gateway, default_interface,
                   interface_address, scan_addresses, scanned_targets, spoof_addresses)

ROOT = Path(__file__).resolve().parent.parent
BG, CARD, TEXT, MUTED, GREEN = "#101923", "#192634", "#e6edf4", "#9bafbe", "#53d3ad"


def named_values(event, key):
    values = event.get(key, [])
    names = event.get(key + "_names", [])
    if not isinstance(values, list):
        return ""
    if not isinstance(names, list):
        names = []
    return ", ".join(f"{names[i]} ({value})" if i < len(names) and names[i] else str(value)
                     for i, value in enumerate(values))


def named_value(event, key, default="Not available"):
    value = event.get(key, default)
    name = event.get(key + "_name")
    return f"{name} ({value})" if name else str(value)


def handshake_text(item):
    client, server = item["client"], item["server"]
    src, sport, dst, dport = item["key"]
    lines = [f"Transport: {item.get('transport', 'TLS')}", f"{src}:{sport}  →  {dst}:{dport}", ""]
    if client:
        lines += ["CLIENT HELLO", f"  Hostname: {client.get('sni') or 'Not available'}"]
        for key, label in (("versions", "Supported versions"), ("alpn", "Protocols")):
            if client.get(key):
                lines.append(f"  {label}: {named_values(client, key)}")
    else:
        lines.append("CLIENT HELLO  ·  Not captured")
    lines.append("")
    if server:
        lines += ["SERVER HELLO", f"  TLS version: {named_value(server, 'version')}",
                  f"  Selected cipher: {named_value(server, 'cipher')}"]
        if server.get("key_share_group"):
            lines.append(f"  Selected key-share group: {named_value(server, 'key_share_group')}")
    else:
        lines.append("SERVER HELLO  ·  Not captured")
    if client:
        for key, label in (("ciphers", "Offered ciphers"), ("groups", "Groups"),
                           ("sig_algs", "Signature algorithms"), ("key_shares", "Key shares")):
            if client.get(key):
                lines += ["", f"{label}: {named_values(client, key)}"]
    lines += ["", "ABOUT THESE FIELDS",
              "Cipher suite: algorithms used to protect the connection.",
              "Groups and key shares: methods used to establish shared keys.",
              "Signature algorithms: methods supported for digital signatures.",
              "Client values are offers; server values show what was selected."]
    return "\n".join(lines)


def packet_text(packet):
    lines = [f"Protocol: {packet.get('protocol', 'Unknown')}", f"Length: {packet.get('length', 0)} bytes",
             "", "ETHERNET", f"  Source MAC: {packet.get('src_mac', 'Unknown')}",
             f"  Destination MAC: {packet.get('dst_mac', 'Unknown')}", "", "NETWORK",
             f"  Source: {packet.get('src') or 'Not available'}",
             f"  Destination: {packet.get('dst') or 'Not available'}"]
    if packet.get("protocol") == "ARP":
        operation = packet.get("arp_op")
        lines.append(f"  ARP operation: { {1: 'Request', 2: 'Reply'}.get(operation, str(operation)) }")
    if packet.get("protocol") in ("TCP", "UDP"):
        lines += ["", packet["protocol"], f"  Source port: {packet.get('sport', 0)}",
                  f"  Destination port: {packet.get('dport', 0)}"]
    raw = packet.get("hex", "")
    if isinstance(raw, str) and raw:
        lines += ["", "FRAME BYTES (first 96 bytes)"]
        lines += [f"  {offset // 2:04x}  " + " ".join(raw[i:i + 2] for i in range(offset, min(offset + 32, len(raw)), 2))
                  for offset in range(0, len(raw), 32)]
    return "\n".join(lines)


def website_text(site, handshakes):
    event = site["event"]
    lines = [f"Hostname: {site['hostname']}", f"Protocol: {site['protocol']}",
             f"Source IP: {site['src']}"]
    if event.get("dst"):
        lines.append(f"Destination IP: {event['dst']}")
    if event.get("sport") is not None:
        lines.append(f"Source port: {event['sport']}")
    if event.get("dport") is not None:
        lines.append(f"Destination port: {event['dport']}")
    handshake = next((item for item in handshakes if item["client"] is event), None)
    if handshake:
        lines += ["", handshake_text(handshake)]
    elif event.get("event") == "quic_hostname":
        lines += ["", "Hostname found in a QUIC Initial handshake."]
    else:
        lines += ["", "The matching handshake is no longer in the recent handshake list."]
    return "\n".join(lines)


class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Netwatch · Packet Capture")
        self.geometry("1200x800")
        self.minsize(780, 550)
        self.attributes("-fullscreen", True)
        self.bind("<Escape>", lambda _event: self.attributes("-fullscreen", False))
        self.bind("<F11>", lambda _event: self.attributes("-fullscreen", not self.attributes("-fullscreen")))
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.process = self.session = self.reader = self.packet_reader = None
        self.messages, self.scan_messages = queue.Queue(), queue.Queue()
        self.scanning = False
        self.scanned_addresses = []
        self.scanned_interface = None
        self.scanned_own = None
        self.scanned_gateway = None
        self.spoof_ready = False
        self.model = CaptureModel()
        self.packet_rows = {}
        self.website_rows = {}
        self.handshake_rows = {}
        self._build()
        self.after(500, self.tick)

    def _build(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        table_font = tkfont.Font(family="Sans", size=10)
        self.time_width = table_font.measure("00:00:00") + 24
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        borderwidth=0, rowheight=table_font.metrics("linespace") + 12, font=table_font)
        style.configure("Treeview.Heading", background="#243749", foreground=MUTED, relief="flat")
        style.map("Treeview", background=[("selected", "#31546a")], foreground=[("selected", TEXT)])
        main = tk.Frame(self, bg=BG, padx=22, pady=18)
        main.pack(fill="both", expand=True)
        header = tk.Frame(main, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="NETWATCH", bg=BG, fg=TEXT, font=("Sans", 20, "bold")).pack(side="left")
        tk.Label(header, text="  /  PACKET CAPTURE", bg=BG, fg=MUTED).pack(side="left")
        tk.Button(header, text="Close", command=self.close, bg="#354859", fg=TEXT,
                  relief="flat", padx=16).pack(side="right", padx=(8, 0))
        self.stop_button = tk.Button(header, text="Stop", command=self.stop, state="disabled", bg="#354859", fg=TEXT, relief="flat", padx=16)
        self.stop_button.pack(side="right", padx=(8, 0))
        self.start_button = tk.Button(header, text="Start capture", command=self.start, bg=GREEN, fg="#10211d", relief="flat", padx=16)
        self.start_button.pack(side="right")
        tk.Button(header, text="Discover devices", command=self.open_discovery, bg="#354859", fg=TEXT, relief="flat", padx=16).pack(side="right", padx=(0, 8))
        self.status = tk.StringVar(value="Ready · capture is stopped")
        tk.Label(main, textvariable=self.status, bg=BG, fg=MUTED, anchor="w").pack(fill="x", pady=(8, 12))
        mode = tk.Frame(main, bg=BG)
        mode.pack(fill="x", pady=(0, 12))
        self.spoof_enabled = tk.BooleanVar(value=False)
        self.spoof_toggle = tk.Checkbutton(mode, text="IPv4 ARP spoofing", variable=self.spoof_enabled,
                                           command=self.update_spoof_controls, bg=BG, fg=TEXT,
                                           selectcolor=CARD, activebackground=BG, activeforeground=TEXT)
        self.spoof_toggle.pack(side="left", padx=(0, 16))
        tk.Label(mode, text="Target IP", bg=BG, fg=MUTED).pack(side="left")
        self.target_entry = tk.Entry(mode, width=18)
        self.target_entry.pack(side="left", padx=(6, 16))
        tk.Label(mode, text="Gateway IP", bg=BG, fg=MUTED).pack(side="left")
        self.gateway_entry = tk.Entry(mode, width=18)
        self.gateway_entry.pack(side="left", padx=(6, 0))
        self.gateway_button = tk.Button(mode, text="Use detected gateway", command=self.fill_gateway,
                                        bg="#354859", fg=TEXT, relief="flat", padx=8)
        self.gateway_button.pack(side="left", padx=(8, 0))
        self.spoof_all = tk.BooleanVar(value=False)
        self.all_toggle = tk.Checkbutton(mode, text="All scanned devices", variable=self.spoof_all,
                                         command=self.update_spoof_controls, bg=BG, fg=TEXT,
                                         selectcolor=CARD, activebackground=BG, activeforeground=TEXT)
        self.all_toggle.pack(side="left", padx=(16, 0))
        self.update_spoof_controls()
        content = tk.Frame(main, bg=BG)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=3, uniform="content")
        content.columnconfigure(1, weight=2, uniform="content")
        content.rowconfigure(0, weight=1)
        packets = tk.Frame(content, bg=CARD, padx=12, pady=12)
        handshakes = tk.Frame(content, bg=CARD, padx=12, pady=12)
        packets.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        handshakes.grid(row=0, column=1, sticky="nsew")
        tabs = ttk.Notebook(packets)
        tabs.pack(fill="both", expand=True)
        websites = tk.Frame(tabs, bg=CARD, padx=8, pady=8)
        packet_tab = tk.Frame(tabs, bg=CARD, padx=8, pady=8)
        tabs.add(websites, text="Observed websites")
        tabs.add(packet_tab, text="Packets")
        tk.Label(websites, text="Observed hostnames · not a complete browsing history", bg=CARD, fg=TEXT, anchor="w").pack(fill="x", pady=(0, 6))
        self.website_tree = self.tree(websites, ("time", "hostname", "src", "protocol"),
                                     ("Time", "Hostname", "Source IP", "Protocol"))
        self.website_tree.column("time", width=self.time_width, minwidth=self.time_width, stretch=False)
        self.website_tree.bind("<<TreeviewSelect>>", self.website_details)
        self.website_detail = self.details(websites, "Select a website to inspect its connection.")
        tk.Label(packet_tab, text="Captured packets · most recent 1,000", bg=CARD, fg=TEXT, anchor="w").pack(fill="x", pady=(0, 6))
        self.packet_tree = self.tree(packet_tab, ("time", "protocol", "src", "dst", "length"),
                                     ("Time", "Protocol", "Source", "Destination", "Bytes"))
        self.packet_tree.column("time", width=self.time_width, minwidth=self.time_width, stretch=False)
        self.packet_tree.column("protocol", width=100, minwidth=90, stretch=False)
        self.packet_tree.column("length", width=90, minwidth=75, stretch=False)
        self.packet_tree.bind("<<TreeviewSelect>>", self.packet_details)
        self.packet_detail = self.details(packet_tab, "Select a packet to inspect its fields.")
        tk.Label(handshakes, text="Recent TLS and QUIC handshakes · messages grouped", bg=CARD, fg=TEXT, anchor="w").pack(fill="x", pady=(0, 6))
        self.handshake_tree = self.tree(handshakes, ("time", "website", "transport", "status"), ("Time", "Hostname / server", "Protocol", "Messages"))
        self.handshake_tree.column("time", width=self.time_width, minwidth=self.time_width, stretch=False)
        self.handshake_tree.bind("<<TreeviewSelect>>", self.handshake_details)
        self.detail = self.details(handshakes, "Select a handshake to inspect its fields.")

    def tree(self, parent, columns, headings):
        holder = tk.Frame(parent, bg=CARD)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=columns, show="headings", height=8)
        for name, title in zip(columns, headings):
            tree.heading(name, text=title, anchor="w")
            tree.column(name, width=150, minwidth=80, anchor="w")
        vertical = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        vertical.pack(side="right", fill="y")
        horizontal.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        return tree

    def details(self, parent, placeholder):
        frame = tk.Frame(parent, bg="#111d28")
        frame.pack(fill="both", expand=True, pady=(10, 0))
        text = tk.Text(frame, height=9, bg="#111d28", fg=TEXT, relief="flat", font=("Monospace", 10), wrap="word", padx=10, pady=8)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        self.set_details(text, placeholder)
        return text

    @staticmethod
    def set_details(widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def show_error(self, title, message, parent=None):
        parent = parent if parent and parent.winfo_exists() else self
        window = tk.Toplevel(parent)
        window.title(title)
        width = min(700, window.winfo_screenwidth())
        height = min(360, window.winfo_screenheight())
        x = (window.winfo_screenwidth() - width) // 2
        y = (window.winfo_screenheight() - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")
        window.transient(parent)
        window.configure(bg=BG)
        frame = tk.Frame(window, bg=BG, padx=24, pady=20)
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text=title, bg=BG, fg=TEXT, font=("Sans", 16, "bold"),
                 anchor="w").pack(fill="x", pady=(0, 12))
        details = self.details(frame, message)
        details.configure(font=("Sans", 11))
        tk.Button(frame, text="Close", command=window.destroy, bg=GREEN, fg="#10211d",
                  relief="flat", padx=20, pady=6).pack(anchor="e", pady=(14, 0))
        window.grab_set()

    def start(self):
        if self.process is not None:
            return
        try:
            interface = default_interface()
            spoof = ()
            if self.spoof_enabled.get():
                gateway = self.gateway_entry.get().strip()
                if self.spoof_all.get():
                    own_ip = interface_address(interface)
                    router = default_gateway(interface)
                    if (self.scanning or self.scanned_interface != interface or
                            self.scanned_own != own_ip or self.scanned_gateway != router):
                        raise ValueError("Scan devices on the current network before choosing all scanned devices.")
                    targets = scanned_targets(self.scanned_addresses, gateway, own_ip, router)
                    first, gateway = spoof_addresses(targets[0], gateway)
                    spoof = (first, gateway, *targets[1:])
                else:
                    spoof = spoof_addresses(self.target_entry.get(), gateway)
            for reader in (self.reader, self.packet_reader):
                if reader: reader.close()
            if self.session: self.session.cleanup()
            self.session = tempfile.TemporaryDirectory(prefix="netwatch-")
            self.reader = JsonLines(os.path.join(self.session.name, "netwatch_tls.jsonl"))
            self.packet_reader = JsonLines(os.path.join(self.session.name, "netwatch_packets.jsonl"))
            self.model = CaptureModel()
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.website_tree.delete(*self.website_tree.get_children())
            self.handshake_tree.delete(*self.handshake_tree.get_children())
            self.packet_rows.clear(); self.handshake_rows.clear()
            self.website_rows.clear()
            self.set_details(self.website_detail, "Select a website to inspect its connection.")
            self.set_details(self.packet_detail, "Select a packet to inspect its fields.")
            self.set_details(self.detail, "Select a handshake to inspect its fields.")
            self.last_error = "authorization cancelled or capture failed"
            self.capture_error_reported = False
            self.spoof_ready = False
            self.capture_spoof = bool(spoof)
            self.process = subprocess.Popen(["pkexec", sys.executable, str(ROOT / "app/capture_helper.py"), str(ROOT / "netwatch"), self.session.name, *spoof],
                                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
            threading.Thread(target=self.read_errors, args=(self.process,), daemon=True).start()
            self.interface = interface
            self.status.set(f"Waiting for authorization · {interface}")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.spoof_toggle.configure(state="disabled")
            self.update_spoof_controls()
        except (OSError, ValueError) as exc:
            self.show_error("Cannot start capture", str(exc))

    def read_errors(self, process):
        for line in process.stderr:
            self.messages.put((process, line.strip()))
        process.stderr.close()

    def update_spoof_controls(self):
        state = "normal" if self.spoof_enabled.get() and self.process is None else "disabled"
        self.target_entry.configure(state="disabled" if self.spoof_all.get() else state)
        self.gateway_entry.configure(state=state)
        self.gateway_button.configure(state=state)
        self.all_toggle.configure(state=state)
        if state == "normal" and not self.gateway_entry.get():
            self.fill_gateway(silent=True)

    def fill_gateway(self, silent=False):
        try:
            gateway = default_gateway(default_interface())
        except (OSError, ValueError) as exc:
            if not silent:
                self.show_error("Cannot detect gateway", str(exc))
            return
        self.gateway_entry.delete(0, "end")
        self.gateway_entry.insert(0, gateway)

    def stop(self):
        if self.process and self.process.stdin:
            self.process.stdin.close()
            self.process.stdin = None
            self.status.set("Stopping capture…")
            self.stop_button.configure(state="disabled")

    def open_discovery(self):
        if getattr(self, "discovery_window", None) and self.discovery_window.winfo_exists():
            self.discovery_window.lift(); return
        self.discovery_window = window = tk.Toplevel(self)
        window.title("Discover IPv4 devices")
        width = min(window.winfo_screenwidth(), max(700, int(window.winfo_screenwidth() * 0.65)))
        height = min(window.winfo_screenheight(), max(550, int(window.winfo_screenheight() * 0.7)))
        window.geometry(f"{width}x{height}+{max(0, (window.winfo_screenwidth() - width) // 2)}+{max(0, (window.winfo_screenheight() - height) // 2)}")
        window.transient(self)
        window.configure(bg=BG)
        frame = tk.Frame(window, bg=BG, padx=20, pady=18); frame.pack(fill="both", expand=True)
        tk.Label(frame, text="LOCAL DEVICES", bg=BG, fg=TEXT, font=("Sans", 16, "bold")).pack(anchor="w")
        tk.Label(frame, text="Responding IPv4 devices on the local subnet", bg=BG, fg=MUTED).pack(anchor="w", pady=(4, 12))
        self.scan_status = tk.StringVar(value="Ready to scan")
        tk.Label(frame, textvariable=self.scan_status, bg=BG, fg=MUTED, wraplength=max(400, width - 80), justify="left").pack(anchor="w", pady=(0, 8))
        self.scan_tree = self.tree(frame, ("ip",), ("IPv4 address",))
        if not self.scanning:
            self.start_scan()

    def start_scan(self):
        if self.scanning: return
        try:
            interface = default_interface()
            own_ip = interface_address(interface)
            try:
                router = default_gateway(interface)
            except (OSError, ValueError):
                router = None
            process = subprocess.Popen(["pkexec", str(ROOT / "netwatch"), "--scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except (OSError, ValueError) as exc:
            self.scan_status.set(f"Could not start scan: {exc}")
            self.show_error("Cannot start scan", str(exc), self.discovery_window)
            return
        self.scanning = True
        self.scanned_addresses = []
        self.scanned_interface = None
        self.scanned_own = self.scanned_gateway = None
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.scan_status.set("Waiting for authorization and scan results…")
        threading.Thread(target=self.collect_scan, args=(process, interface, own_ip, router), daemon=True).start()

    def collect_scan(self, process, interface, own_ip, router):
        stdout, stderr = process.communicate()
        self.scan_messages.put((process.returncode, stdout, stderr, interface, own_ip, router))

    def tick(self):
        while not self.scan_messages.empty():
            code, output, error, interface, own_ip, router = self.scan_messages.get_nowait()
            self.scanning = False
            if not code:
                self.scanned_addresses = scan_addresses(output)
                self.scanned_interface = interface
                self.scanned_own, self.scanned_gateway = own_ip, router
            else:
                reason = error.strip() or "Authorization cancelled or scan failed."
                self.show_error("Network scan failed", reason, getattr(self, "discovery_window", None))
            if getattr(self, "discovery_window", None) and self.discovery_window.winfo_exists():
                if code:
                    self.scan_status.set(f"Scan failed: {reason}")
                else:
                    addresses = self.scanned_addresses
                    for address in addresses: self.scan_tree.insert("", "end", values=(address,))
                    self.scan_status.set(f"Scan complete · {len(addresses)} responding device(s)")
        while not self.messages.empty():
            process, line = self.messages.get_nowait()
            if process is self.process and line:
                self.last_error = line
                if line.startswith("[arp] spoofing "):
                    self.spoof_ready = True
        if self.process:
            try:
                for packet in self.packet_reader.read(): self.add_packet(packet)
                events = self.reader.read()
                for event in events: self.model.add(event)
                if any(isinstance(event, dict) and event.get("event") in
                       ("client_hello", "server_hello", "quic_hostname") for event in events):
                    self.refresh_handshakes()
                    self.refresh_websites()
                if self.packet_reader.file and self.process.poll() is None and self.process.stdin:
                    if self.capture_spoof and not self.spoof_ready:
                        self.status.set(f"Starting IPv4 spoofing · {self.interface}")
                    else:
                        mode = "IPv4 spoofing" if self.capture_spoof else "local capture"
                        self.status.set(f"Capturing packets · {self.interface} · {mode}")
                if self.process.poll() is not None:
                    code = self.process.returncode
                    self.process = None
                    self.start_button.configure(state="normal"); self.stop_button.configure(state="disabled")
                    self.spoof_toggle.configure(state="normal")
                    self.update_spoof_controls()
                    self.status.set(f"Capture ended (exit {code}) · {self.last_error}" if code else "Capture stopped")
                    if code and not self.capture_error_reported:
                        self.show_error("Capture stopped unexpectedly", f"Exit code: {code}\n\n{self.last_error}")
            except (OSError, ValueError) as exc:
                self.stop(); self.status.set(f"Cannot read capture data: {exc}")
                if not self.capture_error_reported:
                    self.capture_error_reported = True
                    self.show_error("Cannot read capture data", str(exc))
        self.after(1000, self.tick)

    def add_packet(self, packet):
        if not isinstance(packet, dict): return
        src = packet.get("src") or packet.get("src_mac", "?")
        dst = packet.get("dst") or packet.get("dst_mac", "?")
        row = self.packet_tree.insert("", 0, values=(self.format_time(packet.get("ts", 0)), packet.get("protocol", "?"), src, dst, packet.get("length", 0)))
        self.packet_rows[row] = packet
        if len(self.packet_rows) > 1000:
            oldest = self.packet_tree.get_children()[-1]
            self.packet_rows.pop(oldest, None)
            self.packet_tree.delete(oldest)

    def packet_details(self, _event):
        selected = self.packet_tree.selection()
        packet = self.packet_rows.get(selected[0]) if selected else None
        if packet: self.set_details(self.packet_detail, packet_text(packet))

    def refresh_websites(self):
        selected = self.website_tree.selection()
        selected_site = self.website_rows.get(selected[0]) if selected else None
        self.website_tree.delete(*self.website_tree.get_children())
        self.website_rows.clear()
        for site in self.model.websites:
            row = self.website_tree.insert("", "end", values=(self.format_time(site["ts"]), site["hostname"],
                                                               site["src"], site["protocol"]))
            self.website_rows[row] = site
            if site is selected_site:
                self.website_tree.selection_set(row)
                self.set_details(self.website_detail, website_text(site, self.model.handshakes))

    def website_details(self, _event):
        selected = self.website_tree.selection()
        site = self.website_rows.get(selected[0]) if selected else None
        if site:
            self.set_details(self.website_detail, website_text(site, self.model.handshakes))

    def refresh_handshakes(self):
        selected = self.handshake_tree.selection()
        selected_item = self.handshake_rows.get(selected[0]) if selected else None
        self.handshake_tree.delete(*self.handshake_tree.get_children()); self.handshake_rows.clear()
        for item in self.model.handshakes:
            client, server = item["client"], item["server"]
            name = (client.get("sni") if client else None) or item["key"][2]
            status = "Client + server" if client and server else "Server not observed" if client else "Client not observed"
            row = self.handshake_tree.insert("", "end", values=(self.format_time(item["ts"]), name, item["transport"], status))
            self.handshake_rows[row] = item
            if item is selected_item: self.handshake_tree.selection_set(row)

    def handshake_details(self, _event):
        selected = self.handshake_tree.selection()
        item = self.handshake_rows.get(selected[0]) if selected else None
        if item: self.set_details(self.detail, handshake_text(item))

    @staticmethod
    def format_time(timestamp):
        try: return time.strftime("%H:%M:%S", time.localtime(timestamp))
        except (OSError, OverflowError, TypeError, ValueError): return "—"

    def close(self):
        self.stop()
        for reader in (self.reader, self.packet_reader):
            if reader: reader.close()
        if self.process is None and self.session: self.session.cleanup()
        self.destroy()


if __name__ == "__main__":
    Dashboard().mainloop()
