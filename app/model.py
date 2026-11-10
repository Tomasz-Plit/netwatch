"""Parse Netwatch's existing JSONL stream and group observations for the UI."""
from collections import Counter, deque
import json
import os
import time

CATEGORIES = {
    "Video": ("youtube.com", "youtu.be", "netflix.com", "twitch.tv", "vimeo.com", "googlevideo.com"),
    "Social": ("reddit.com", "instagram.com", "facebook.com", "tiktok.com", "x.com", "twitter.com", "linkedin.com", "discord.com"),
    "Shopping": ("amazon.com", "amazon.pl", "allegro.pl", "ebay.com", "aliexpress.com"),
    "Work & tools": ("github.com", "gitlab.com", "stackoverflow.com", "openai.com", "slack.com", "microsoft.com", "office.com"),
    "News": ("bbc.com", "bbc.co.uk", "reuters.com", "apnews.com", "theguardian.com"),
    "Music": ("spotify.com", "soundcloud.com", "bandcamp.com"),
}


def category_for(hostname):
    name = hostname.lower().rstrip(".")
    for category, domains in CATEGORIES.items():
        if any(name == domain or name.endswith("." + domain) for domain in domains):
            return category
    return "Other"


def default_interface(route_path="/proc/net/route"):
    with open(route_path, encoding="ascii") as routes:
        next(routes, None)
        for line in routes:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 1:
                return fields[0]
    raise ValueError("No active default IPv4 route found")


def interface_bytes(interface):
    if not interface or "/" in interface or interface in (".", ".."):
        raise ValueError("Invalid interface name")
    base = f"/sys/class/net/{interface}/statistics"
    with open(f"{base}/rx_bytes", encoding="ascii") as stream:
        rx = int(stream.read())
    with open(f"{base}/tx_bytes", encoding="ascii") as stream:
        tx = int(stream.read())
    return rx, tx


class CaptureModel:
    def __init__(self):
        self.handshakes = deque(maxlen=200)
        self.websites = deque(maxlen=500)
        self.categories = Counter()
        self.observations = 0

    def add(self, event):
        if not isinstance(event, dict):
            return
        kind = event.get("event")
        if kind not in ("client_hello", "server_hello"):
            return
        src, dst = event.get("src"), event.get("dst")
        sport, dport = event.get("sport"), event.get("dport")
        if not all(isinstance(x, str) and x for x in (src, dst)) or not all(type(x) is int and 0 < x < 65536 for x in (sport, dport)):
            return
        ts = event.get("ts", 0)
        if not isinstance(ts, (int, float)):
            ts = 0
        client = kind == "client_hello"
        key = (src, sport, dst, dport) if client else (dst, dport, src, sport)
        match = next((item for item in self.handshakes if item["key"] == key
                      and abs(ts - item["ts"]) <= 120
                      and ((client and item["client"] is None and item["server"] is not None)
                           or (not client and item["server"] is None and item["client"] is not None))), None)
        if match is None:
            match = {"key": key, "ts": ts, "client": None, "server": None}
            self.handshakes.appendleft(match)
        match["client" if client else "server"] = event
        hostname = event.get("sni")
        if client and isinstance(hostname, str) and hostname:
            category = category_for(hostname)
            self.websites.appendleft({"host": hostname, "ip": src, "category": category, "ts": ts})
            self.categories[category] += 1
            self.observations += 1


class JsonLines:
    def __init__(self, path):
        self.path = path
        self.file = None
        self.identity = None
        self.pending = b""
        self.discarding = False

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def read(self):
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return []
        if self.file and ((stat.st_dev, stat.st_ino) != self.identity or stat.st_size < self.file.tell()):
            self.close()
            self.pending = b""
            self.discarding = False
        if not self.file:
            self.file = open(self.path, "rb")
            actual = os.fstat(self.file.fileno())
            self.identity = (actual.st_dev, actual.st_ino)
        chunk = self.file.read(1024 * 1024)
        events = []
        for part in chunk.splitlines(keepends=True):
            if self.discarding:
                if part.endswith(b"\n"):
                    self.discarding = False
                continue
            self.pending += part
            if len(self.pending) > 65536:
                self.pending = b""
                self.discarding = not part.endswith(b"\n")
            elif part.endswith(b"\n"):
                try:
                    events.append(json.loads(self.pending))
                except (ValueError, UnicodeDecodeError):
                    pass
                self.pending = b""
        return events
