"""Parse Netwatch's existing JSONL stream and group observations for the UI."""
from collections import deque
import json
import ipaddress
import os
import fcntl
import socket
import struct
import sys


def spoof_addresses(target, gateway):
    try:
        target = str(ipaddress.IPv4Address(target.strip()))
        gateway = str(ipaddress.IPv4Address(gateway.strip()))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Enter valid IPv4 addresses for the target and gateway.") from exc
    if target == gateway:
        raise ValueError("The target and gateway must be different addresses.")
    return target, gateway


def scan_addresses(output):
    """Extract addresses from the CLI scan output, ignoring headers and duplicates."""
    found = []
    seen = set()
    for line in output.splitlines():
        try:
            address = str(ipaddress.IPv4Address(line.strip()))
        except ipaddress.AddressValueError:
            continue
        if address not in seen:
            found.append(address)
            seen.add(address)
    return found


def default_interface(route_path="/proc/net/route"):
    with open(route_path, encoding="ascii") as routes:
        next(routes, None)
        for line in routes:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 1:
                return fields[0]
    raise ValueError("No active default IPv4 route found")


def default_gateway(interface, route_path="/proc/net/route"):
    with open(route_path, encoding="ascii") as routes:
        next(routes, None)
        for line in routes:
            fields = line.split()
            if len(fields) >= 4 and fields[0] == interface and fields[1] == "00000000":
                flags, gateway = int(fields[3], 16), int(fields[2], 16)
                if flags & 3 == 3 and 0 < gateway <= 0xffffffff:
                    return str(ipaddress.IPv4Address(gateway.to_bytes(4, sys.byteorder)))
    raise ValueError(f"No default IPv4 gateway found for {interface}.")


def interface_address(interface):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = struct.pack("256s", interface.encode()[:15])
        result = fcntl.ioctl(sock.fileno(), 0x8915, request)  # SIOCGIFADDR
        return socket.inet_ntoa(result[20:24])


def scanned_targets(addresses, gateway, own_ip, default_router):
    excluded = {gateway, own_ip, default_router}
    targets = list(dict.fromkeys(address for address in addresses if address not in excluded))
    if not targets:
        raise ValueError("No client devices were found in the last scan.")
    if len(targets) > 64:
        raise ValueError("The last scan found more than 64 clients; select a single target instead.")
    return targets


class CaptureModel:
    def __init__(self):
        self.handshakes = deque(maxlen=200)
        self.websites = deque(maxlen=1000)

    def add(self, event):
        if not isinstance(event, dict):
            return
        kind = event.get("event")
        if kind in ("client_hello", "quic_hostname"):
            hostname, src = event.get("sni"), event.get("src")
            if isinstance(hostname, str) and hostname and isinstance(src, str) and src:
                self.websites.appendleft({"hostname": hostname, "src": src,
                                          "protocol": "QUIC" if kind == "quic_hostname" else "TLS",
                                          "ts": event.get("ts", 0), "event": event})
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
