#!/usr/bin/env python3
"""Local desktop dashboard for the Netwatch capture engine."""
import os
import math
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkfont

from model import CaptureModel, JsonLines, default_interface, interface_bytes

ROOT = Path(__file__).resolve().parent.parent
BG = "#101923"
CARD = "#192634"
TEXT = "#e6edf4"
MUTED = "#9bafbe"
GREEN = "#53d3ad"
BLUE = "#65a6ff"
CATEGORY_COLORS = ("#5ccfba", "#7ca8ff", "#f2bd72", "#b994ef", "#ec91a4", "#7fbfdf", "#8292a2")


def handshake_text(item):
    client, server = item["client"], item["server"]
    source, sport, destination, dport = item["key"]
    lines = [f"{source}:{sport}  →  {destination}:{dport}", ""]
    if client:
        lines.extend(["CLIENT HELLO", f"  Hostname: {client.get('sni') or 'Not available'}"])
        for key, label in (("versions", "Supported versions"), ("alpn", "Protocols")):
            values = client.get(key)
            if isinstance(values, list) and values:
                lines.append(f"  {label}: {', '.join(map(str, values))}")
    else:
        lines.append("CLIENT HELLO  ·  Not captured")
    lines.append("")
    if server:
        lines.extend(["SERVER HELLO", f"  TLS version: {server.get('version', 'Not available')}",
                      f"  Selected cipher: {server.get('cipher', 'Not available')}"])
        if server.get("key_share_group"):
            lines.append(f"  Key share group: {server['key_share_group']}")
        if isinstance(server.get("client_to_server_hello_ms"), (int, float)):
            lines.append(f"  Response time: {server['client_to_server_hello_ms']:.1f} ms")
    else:
        lines.append("SERVER HELLO  ·  Not captured")
    if client:
        for key, label in (("ciphers", "Offered ciphers"), ("groups", "Groups"),
                           ("sig_algs", "Signature algorithms"), ("key_shares", "Key shares")):
            values = client.get(key)
            if isinstance(values, list) and values:
                lines.extend(["", f"{label}:  {', '.join(map(str, values))}"])
    return "\n".join(lines)


def rate(value):
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if value < 1000 or unit == "GB/s":
            return f"{value:.1f} {unit}"
        value /= 1000


def graph_scale(peak):
    """Round up to a readable scale without hiding small amounts of traffic."""
    if peak <= 0:
        return 1000
    magnitude = 10 ** math.floor(math.log10(peak))
    for step in (1, 2, 5, 10):
        if peak <= step * magnitude:
            return step * magnitude


class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Netwatch")
        self.geometry("1200x880")
        self.minsize(850, 660)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.process = None
        self.reader = None
        self.session = None
        self.messages = queue.Queue()
        self.model = CaptureModel()
        self.interface = None
        self.previous = None
        self.download = [0] * 60
        self.upload = [0] * 60
        self.filter_category = None
        self.handshake_rows = {}
        self._build()
        self.after(500, self.tick)

    def _build(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        self.table_font = tkfont.Font(family="Sans", size=10)
        self.graph_font = tkfont.Font(family="Sans", size=9)
        self.time_column_width = self.table_font.measure("00:00:00") + 24
        style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                        borderwidth=0, rowheight=self.table_font.metrics("linespace") + 12,
                        font=self.table_font)
        style.configure("Treeview.Heading", background="#243749", foreground=MUTED,
                        relief="flat", font=("Sans", 9, "bold"))
        style.map("Treeview", background=[("selected", "#31546a")], foreground=[("selected", TEXT)])
        main = tk.Frame(self, bg=BG, padx=24, pady=18)
        main.pack(fill="both", expand=True)
        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", pady=(0, 10))
        tk.Label(header, text="NETWATCH", bg=BG, fg=TEXT, font=("Sans", 20, "bold")).pack(side="left")
        tk.Label(header, text="  /  LOCAL CAPTURE", bg=BG, fg=MUTED, font=("Sans", 10)).pack(side="left", pady=(8, 0))
        self.stop_button = tk.Button(header, text="Stop", command=self.stop, state="disabled",
                                     bg="#354859", fg=TEXT, relief="flat", padx=16, pady=6)
        self.stop_button.pack(side="right", padx=(8, 0))
        self.start_button = tk.Button(header, text="Start capture", command=self.start,
                                      bg=GREEN, fg="#10211d", relief="flat", padx=16, pady=6)
        self.start_button.pack(side="right")
        self.status = tk.StringVar(value="Ready · capture is stopped")
        tk.Label(main, textvariable=self.status, bg=BG, fg=MUTED, anchor="w").pack(fill="x", pady=(0, 12))
        self.down_graph = self.make_graph(main, "DOWNLOAD", BLUE)
        self.up_graph = self.make_graph(main, "UPLOAD", GREEN)
        middle = tk.Frame(main, bg=BG)
        middle.pack(fill="both", expand=True, pady=(6, 10))
        middle.columnconfigure(0, weight=2, uniform="middle")
        middle.columnconfigure(1, weight=3, uniform="middle")
        middle.rowconfigure(0, weight=1)
        categories = tk.Frame(middle, bg=CARD, padx=14, pady=12)
        categories.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.label(categories, "WEBSITE CATEGORIES", 11, True).pack(anchor="w")
        self.label(categories, "Share of hostname observations", 9, color=MUTED).pack(anchor="w", pady=(3, 2))
        self.categories = tk.Canvas(categories, bg=CARD, highlightthickness=0, height=220)
        self.categories.pack(fill="both", expand=True)
        self.categories.bind("<Configure>", lambda _event: self.draw_categories())
        self.categories.bind("<Button-1>", self.category_clicked)
        self.category_status = tk.StringVar(value="All categories")
        tk.Button(categories, textvariable=self.category_status, command=lambda: self.set_filter(None),
                  bg="#2b4050", fg=TEXT, relief="flat").pack(anchor="w", pady=(5, 0))
        handshakes = tk.Frame(middle, bg=CARD, padx=14, pady=12)
        handshakes.grid(row=0, column=1, sticky="nsew")
        self.label(handshakes, "TLS HANDSHAKES", 11, True).pack(anchor="w")
        self.label(handshakes, "Select a row for handshake details", 9, color=MUTED).pack(anchor="w", pady=(3, 8))
        self.handshake_tree = self.tree(handshakes, ("time", "website", "status"), ("Time", "Hostname / server", "Messages"))
        self.handshake_tree.column("time", width=self.time_column_width, minwidth=self.time_column_width, stretch=False)
        status_width = self.table_font.measure("Client + server") + 24
        self.handshake_tree.column("status", width=status_width, minwidth=status_width, stretch=False)
        self.handshake_tree.bind("<<TreeviewSelect>>", self.handshake_details)
        detail_frame = tk.Frame(handshakes, bg="#111d28")
        detail_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.detail = tk.Text(detail_frame, height=6, bg="#111d28", fg=TEXT, relief="flat",
                              font=("Sans", 10), wrap="word", padx=10, pady=8)
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side="right", fill="y")
        self.detail.pack(fill="both", expand=True)
        self.detail.insert("1.0", "Select a handshake to view its messages.")
        self.detail.configure(state="disabled")
        bottom = tk.Frame(main, bg=CARD, padx=14, pady=12)
        bottom.pack(fill="both", expand=True)
        self.label(bottom, "RECENT WEBSITE OBSERVATIONS", 11, True).pack(anchor="w")
        self.label(bottom, "TLS hostnames only · observations are not complete browsing history", 9, color=MUTED).pack(anchor="w", pady=(3, 8))
        self.website_tree = self.tree(bottom, ("time", "website", "category", "visitor"),
                                      ("Time", "Hostname", "Category", "Client IP"))
        self.website_tree.column("time", width=self.time_column_width, minwidth=self.time_column_width, stretch=False)
        category_width = self.table_font.measure("Work & tools") + 24
        self.website_tree.column("category", width=category_width, minwidth=category_width, stretch=False)
        self.website_tree.column("visitor", width=180)

    def label(self, parent, text, size, bold=False, color=TEXT):
        return tk.Label(parent, text=text, bg=CARD, fg=color, anchor="w", font=("Sans", size, "bold" if bold else "normal"))

    def tree(self, parent, columns, headings):
        holder = tk.Frame(parent, bg=CARD)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=columns, show="headings", height=5)
        for name, title in zip(columns, headings):
            tree.heading(name, text=title, anchor="w")
            tree.column(name, width=150, minwidth=80, anchor="w")
        bar = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=bar.set, xscrollcommand=horizontal.set)
        bar.pack(side="right", fill="y")
        horizontal.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        return tree

    def make_graph(self, parent, title, color):
        frame = tk.Frame(parent, bg=CARD, padx=14, pady=9)
        frame.pack(fill="x", pady=(0, 8))
        row = tk.Frame(frame, bg=CARD)
        row.pack(fill="x")
        self.label(row, title, 10, True).pack(side="left")
        value = tk.StringVar(value="—")
        tk.Label(row, textvariable=value, bg=CARD, fg=color, font=("Sans", 14, "bold")).pack(side="right")
        canvas = tk.Canvas(frame, height=100, bg=CARD, highlightthickness=0)
        canvas.pack(fill="x")
        return canvas, value, color

    def draw_graph(self, graph, data):
        canvas, value, color = graph
        canvas.delete("all")
        w, h = max(canvas.winfo_width(), 2), max(canvas.winfo_height(), 2)
        maximum = graph_scale(max(data))
        labels = [rate(maximum), rate(maximum / 2), rate(0)]
        left = max(self.graph_font.measure(label) for label in labels) + 14
        top = self.graph_font.metrics("linespace") / 2 + 2
        bottom = h - self.graph_font.metrics("linespace") - 5
        right = max(left + 1, w - 8)
        if bottom <= top:
            return
        for index, label in enumerate(labels):
            y = top + (bottom - top) * index / 2
            canvas.create_line(left, y, right, y, fill="#2a3947")
            canvas.create_text(left - 8, y, text=label, anchor="e", fill=MUTED, font=self.graph_font)
        canvas.create_text(left, h - 2, text="60 seconds ago", anchor="sw", fill=MUTED, font=self.graph_font)
        canvas.create_text(right, h - 2, text="now", anchor="se", fill=MUTED, font=self.graph_font)
        points = []
        for i, sample in enumerate(data):
            points.extend((left + i * (right - left) / (len(data) - 1),
                           bottom - sample / maximum * (bottom - top)))
        fill = "#243d59" if graph is self.down_graph else "#1e483f"
        canvas.create_polygon(left, bottom, *points, right, bottom, fill=fill, outline="")
        canvas.create_line(*points, fill=color, width=2)
        value.set(rate(data[-1]))

    def start(self):
        if self.process is not None:
            return
        try:
            self.interface = default_interface()
            self.previous = (*interface_bytes(self.interface), time.monotonic())
            if self.reader:
                self.reader.close()
            if self.session:
                self.session.cleanup()
            self.session = tempfile.TemporaryDirectory(prefix="netwatch-")
            self.model = CaptureModel()
            self.reader = JsonLines(os.path.join(self.session.name, "netwatch_tls.jsonl"))
            self.download = [0] * 60
            self.upload = [0] * 60
            self.filter_category = None
            self.last_error = "authorization cancelled or capture failed"
            self.refresh()
            self.process = subprocess.Popen(
                ["pkexec", sys.executable, str(ROOT / "app/capture_helper.py"),
                 str(ROOT / "netwatch"), self.session.name],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                text=True, bufsize=1)
            process = self.process
            threading.Thread(target=self.read_errors, args=(process,), daemon=True).start()
            self.status.set(f"Waiting for authorization · {self.interface}")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
        except (OSError, ValueError) as exc:
            if self.reader:
                self.reader.close(); self.reader = None
            if self.session:
                self.session.cleanup(); self.session = None
            messagebox.showerror("Cannot start capture", str(exc))

    def read_errors(self, process):
        for line in process.stderr:
            self.messages.put((process, line.strip()))
        process.stderr.close()

    def stop(self):
        if self.process and self.process.stdin:
            self.process.stdin.close()
            self.process.stdin = None
            self.status.set("Stopping capture…")
            self.stop_button.configure(state="disabled")

    def tick(self):
        while True:
            try:
                process, line = self.messages.get_nowait()
            except queue.Empty:
                break
            if process is self.process and line:
                self.last_error = line
        if self.process:
            try:
                if self.reader:
                    events = self.reader.read()
                    for event in events:
                        self.model.add(event)
                    if events:
                        self.refresh()
                    if self.reader.file and self.process.poll() is None and self.process.stdin:
                        self.status.set(f"Capturing · {self.interface} · TLS hostnames only")
                if self.process.poll() is not None:
                    code = self.process.returncode
                    self.process = None
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    if code:
                        self.status.set(f"Capture ended (exit {code}) · {getattr(self, 'last_error', 'authorization cancelled or capture failed')}")
                    else:
                        self.status.set("Capture stopped")
                else:
                    rx, tx = interface_bytes(self.interface)
                    now = time.monotonic()
                    old_rx, old_tx, previous_time = self.previous
                    elapsed = max(now - previous_time, 0.001)
                    self.download = self.download[1:] + [max(0, rx - old_rx) / elapsed]
                    self.upload = self.upload[1:] + [max(0, tx - old_tx) / elapsed]
                    self.previous = (rx, tx, now)
            except (OSError, ValueError) as exc:
                self.status.set(f"Cannot read capture data: {exc}")
                self.stop()
        self.draw_graph(self.down_graph, self.download)
        self.draw_graph(self.up_graph, self.upload)
        self.after(1000, self.tick)

    def set_filter(self, category):
        self.filter_category = category
        self.refresh()

    def draw_categories(self):
        canvas = self.categories
        canvas.delete("all")
        width, height = canvas.winfo_width(), canvas.winfo_height()
        counts = self.model.categories.most_common()
        if not counts:
            canvas.create_text(width / 2, height / 2, text="No websites observed yet",
                               fill=MUTED, font=("Sans", 10))
            return
        total = sum(count for _, count in counts)
        legend_width = max(self.graph_font.measure(f"{category}  100%") for category, _ in counts) + 38
        diameter = max(30, min(width - legend_width - 28, height - 16, 300))
        left, top = 8, max(8, (height - diameter) / 2)
        start = 90
        for index, (category, count) in enumerate(counts):
            color = CATEGORY_COLORS[index % len(CATEGORY_COLORS)]
            extent = 360 * count / total
            if len(counts) == 1:
                canvas.create_oval(left, top, left + diameter, top + diameter,
                                   fill=color, outline=CARD, width=2, tags=(f"category-{index}",))
            else:
                canvas.create_arc(left, top, left + diameter, top + diameter, start=start,
                                  extent=-extent, fill=color, outline=CARD, width=2,
                                  tags=(f"category-{index}",))
            start -= extent
        canvas.create_oval(left + diameter * .29, top + diameter * .29,
                           left + diameter * .71, top + diameter * .71,
                           fill=CARD, outline=CARD)
        center_y = top + diameter / 2
        canvas.create_text(left + diameter / 2, center_y - 4, text=str(total), anchor="s",
                           fill=TEXT, font=("Sans", 16, "bold"))
        canvas.create_text(left + diameter / 2, center_y + 4, text="observations", anchor="n",
                           fill=MUTED, font=("Sans", 8))
        legend_x = left + diameter + 18
        legend_spacing = self.graph_font.metrics("linespace") + 8
        for index, (category, count) in enumerate(counts):
            y = max(legend_spacing / 2, (height - len(counts) * legend_spacing) / 2 + legend_spacing / 2) + index * legend_spacing
            if y > height - 8:
                break
            tags = (f"category-{index}",)
            canvas.create_oval(legend_x, y - 4, legend_x + 9, y + 5,
                               fill=CATEGORY_COLORS[index % len(CATEGORY_COLORS)], outline="", tags=tags)
            canvas.create_text(legend_x + 16, y, anchor="w", fill=TEXT, font=self.graph_font,
                               text=f"{category}  {count / total:.0%}", tags=tags)

    def category_clicked(self, event):
        for item in self.categories.find_overlapping(event.x, event.y, event.x, event.y):
            for tag in self.categories.gettags(item):
                if tag.startswith("category-"):
                    index = int(tag.removeprefix("category-"))
                    counts = self.model.categories.most_common()
                    if index < len(counts):
                        self.set_filter(counts[index][0])
                    return

    def refresh(self):
        self.category_status.set(f"Filter: {self.filter_category}  ×" if self.filter_category else "All categories")
        self.draw_categories()
        self.website_tree.delete(*self.website_tree.get_children())
        for site in self.model.websites:
            if self.filter_category and site["category"] != self.filter_category:
                continue
            self.website_tree.insert("", "end", values=(self.format_time(site["ts"]), site["host"], site["category"], site["ip"]))
        selected = self.handshake_tree.selection()
        selected_item = self.handshake_rows.get(selected[0]) if selected else None
        self.handshake_tree.delete(*self.handshake_tree.get_children())
        self.handshake_rows = {}
        for handshake in self.model.handshakes:
            client, server = handshake["client"], handshake["server"]
            name = client.get("sni") if client else None
            name = name or handshake["key"][2]
            status = "Client + server" if client and server else "Client only" if client else "Server only"
            row = self.handshake_tree.insert("", "end", values=(self.format_time(handshake["ts"]), name, status))
            self.handshake_rows[row] = handshake
            if handshake is selected_item:
                self.handshake_tree.selection_set(row)

    def handshake_details(self, _event):
        selected = self.handshake_tree.selection()
        item = self.handshake_rows.get(selected[0]) if selected else None
        if not item:
            return
        text = handshake_text(item)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    @staticmethod
    def format_time(timestamp):
        try:
            return time.strftime("%H:%M:%S", time.localtime(timestamp))
        except (OSError, OverflowError, ValueError):
            return "—"

    def close(self):
        self.stop()
        if self.reader:
            self.reader.close()
        if self.process is None and self.session:
            self.session.cleanup()
        # The helper exits on stdin EOF even if the window is closed during authorization.
        self.destroy()


if __name__ == "__main__":
    Dashboard().mainloop()
