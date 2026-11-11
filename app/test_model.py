import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from model import (CaptureModel, JsonLines, default_gateway, default_interface,
                   scan_addresses, scanned_targets, spoof_addresses)
from main import handshake_text, packet_text, website_text


class ModelTests(unittest.TestCase):
    def test_quic_handshakes_are_displayed_and_separate_from_tcp(self):
        model = CaptureModel()
        client = {"event": "client_hello", "transport": "QUIC", "src": "192.0.2.1", "dst": "192.0.2.2",
                  "sport": 1234, "dport": 443, "sni": "example.com", "ts": 1, "alpn": ["h3"]}
        server = {"event": "server_hello", "transport": "QUIC", "src": "192.0.2.2", "dst": "192.0.2.1",
                  "sport": 443, "dport": 1234, "cipher": "0x1301", "ts": 2}
        model.add(client)
        model.add({**server, "transport": "TLS"})
        self.assertEqual(len(model.handshakes), 2)
        model.add(server)
        quic = next(item for item in model.handshakes if item["transport"] == "QUIC")
        self.assertIs(quic["server"], server)
        self.assertEqual(model.websites[0]["protocol"], "QUIC")
        self.assertIn("Protocols: h3", website_text(model.websites[0], model.handshakes))
        self.assertIn("Selected cipher: 0x1301", website_text(model.websites[0], model.handshakes))

    def test_websites_from_c_tls_and_quic_events(self):
        model = CaptureModel()
        model.add({"event": "client_hello", "src": "192.0.2.1", "dst": "192.0.2.2",
                   "sport": 1234, "dport": 443, "sni": "example.com", "ts": 1})
        model.add({"event": "quic_hostname", "src": "192.0.2.3", "sni": "example.org", "ts": 2})
        self.assertEqual([(site["hostname"], site["protocol"]) for site in model.websites],
                         [("example.org", "QUIC"), ("example.com", "TLS")])
        self.assertEqual(len(model.handshakes), 1)

    def test_website_details_show_matching_handshake_or_quic_endpoints(self):
        model = CaptureModel()
        client = {"event": "client_hello", "src": "192.0.2.1", "dst": "192.0.2.2",
                  "sport": 1234, "dport": 443, "sni": "example.com", "ts": 1}
        model.add(client)
        site = model.websites[0]
        self.assertIn("SERVER HELLO  ·  Not captured", website_text(site, model.handshakes))
        model.add({"event": "server_hello", "src": "192.0.2.2", "dst": "192.0.2.1",
                   "sport": 443, "dport": 1234, "cipher": "0x1301", "ts": 2})
        self.assertIn("Selected cipher: 0x1301", website_text(site, model.handshakes))
        model.add({"event": "quic_hostname", "src": "192.0.2.1", "dst": "192.0.2.9",
                   "sport": 1234, "dport": 443, "sni": "example.org", "ts": 3})
        details = website_text(model.websites[0], model.handshakes)
        self.assertIn("Destination IP: 192.0.2.9", details)
        self.assertIn("Destination port: 443", details)

    def test_spoof_addresses_validate_target_and_gateway(self):
        self.assertEqual(spoof_addresses(" 192.0.2.2 ", "192.0.2.1"), ("192.0.2.2", "192.0.2.1"))
        for target, gateway in (("invalid", "192.0.2.1"), ("192.0.2.1", "192.0.2.1"), ("::1", "192.0.2.1")):
            with self.assertRaises(ValueError):
                spoof_addresses(target, gateway)

    def test_scan_addresses_ignores_headers_invalid_and_duplicates(self):
        output = "Detected interface: wlan0\nReachable IPv4 addresses:\n192.168.1.1\n192.168.1.2\n192.168.1.1\n300.1.1.1\n"
        self.assertEqual(scan_addresses(output), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(scan_addresses("no replies\n"), [])

    def test_arp_packet_details(self):
        packet = {"protocol": "ARP", "length": 42, "src": "192.0.2.1", "dst": "192.0.2.2",
                  "arp_op": 1, "hex": "00010203"}
        text = packet_text(packet)
        self.assertIn("ARP operation: Request", text)
        self.assertIn("00 01 02 03", text)

    def test_handshake_details_include_both_sides_or_missing_message(self):
        item = {"key": ("a", 1234, "b", 443), "client": {"sni": "example.com", "alpn": ["h2"]},
                "server": {"version": "0x0304", "cipher": "0x1301"}}
        text = handshake_text(item)
        self.assertIn("Hostname: example.com", text)
        self.assertIn("Protocols: h2", text)
        self.assertIn("Selected cipher: 0x1301", text)
        item["server"] = None
        self.assertIn("SERVER HELLO  ·  Not captured", handshake_text(item))

    def test_handshake_details_show_names_and_keep_unknown_codes(self):
        item = {"key": ("a", 1234, "b", 443),
                "client": {"ciphers": ["0x1301", "0xffff"],
                           "ciphers_names": ["TLS_AES_128_GCM_SHA256", None],
                           "groups": ["0x001d"], "groups_names": ["x25519"]},
                "server": {"version": "0x0304", "version_name": "TLS 1.3",
                           "cipher": "0x1301", "cipher_name": "TLS_AES_128_GCM_SHA256"}}
        details = handshake_text(item)
        self.assertIn("TLS_AES_128_GCM_SHA256 (0x1301)", details)
        self.assertIn("0xffff", details)
        self.assertIn("x25519 (0x001d)", details)
        self.assertIn("TLS 1.3 (0x0304)", details)

    def test_handshake_pairing_and_reused_port(self):
        model = CaptureModel()
        client = {"event": "client_hello", "src": "192.0.2.1", "sport": 50123,
                  "dst": "203.0.113.1", "dport": 443, "sni": "www.youtube.com", "ts": 10}
        server = {"event": "server_hello", "src": "203.0.113.1", "sport": 443,
                  "dst": "192.0.2.1", "dport": 50123, "ts": 11}
        model.add(client)
        model.add(server)
        self.assertEqual(len(model.handshakes), 1)
        self.assertEqual(model.handshakes[0]["client"], client)
        self.assertEqual(model.handshakes[0]["server"], server)
        model.add({**client, "ts": 20})
        self.assertEqual(len(model.handshakes), 2)
        self.assertIsNone(model.handshakes[0]["server"])

    def test_out_of_order_and_unrelated_or_old_hello(self):
        model = CaptureModel()
        server = {"event": "server_hello", "src": "b", "sport": 443, "dst": "a", "dport": 1, "ts": 100}
        client = {"event": "client_hello", "src": "a", "sport": 1, "dst": "b", "dport": 443, "ts": 99}
        model.add(server)
        model.add(client)
        self.assertEqual(len(model.handshakes), 1)
        model.add({**server, "dport": 2})
        model.add({**client, "sport": 2, "ts": 400})
        self.assertEqual(len(model.handshakes), 3)
        model.add({"event": "client_hello", "src": "a"})
        self.assertEqual(len(model.handshakes), 3)

    def test_partial_and_invalid_json_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.jsonl"
            reader = JsonLines(path)
            self.assertEqual(reader.read(), [])
            path.write_text('{"event":"client_', encoding="utf-8")
            self.assertEqual(reader.read(), [])
            with path.open("a", encoding="utf-8") as f:
                f.write('hello"}\ninvalid\n' + json.dumps({"event": "server_hello"}) + '\n')
            self.assertEqual([e["event"] for e in reader.read()], ["client_hello", "server_hello"])
            reader.close()

    def test_first_active_default_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "route"
            path.write_text("header\neth0 00000000 00000000 0000\nwlan0 00000000 01010101 0003\n", encoding="ascii")
            self.assertEqual(default_interface(path), "wlan0")

    def test_gateway_from_selected_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "route"
            gateway = int.from_bytes(bytes([192, 168, 1, 1]), sys.byteorder)
            path.write_text(f"header\neth0 00000000 {gateway:08X} 0003\nwlan0 00000000 {gateway:08X} 0003\n", encoding="ascii")
            self.assertEqual(default_gateway("wlan0", path), "192.168.1.1")
            with self.assertRaises(ValueError): default_gateway("missing", path)

    def test_all_scanned_excludes_computer_and_routers(self):
        addresses = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.3", "192.168.1.4"]
        self.assertEqual(scanned_targets(addresses, "192.168.1.4", "192.168.1.2", "192.168.1.1"), ["192.168.1.3"])
        with self.assertRaises(ValueError): scanned_targets(addresses[:2], "192.168.1.1", "192.168.1.2", "192.168.1.1")
        with self.assertRaises(ValueError): scanned_targets([f"10.0.0.{n}" for n in range(1, 66)], "192.0.2.1", "192.0.2.2", "192.0.2.1")

    def test_helper_stops_capture_when_control_pipe_closes(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "capture"
            marker = Path(directory) / "ready"
            executable.write_text(
                "#!/usr/bin/env python3\nimport pathlib, signal, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: exit(0))\n"
                "pathlib.Path('ready').touch()\nwhile True: time.sleep(.05)\n",
                encoding="utf-8")
            os.chmod(executable, 0o755)
            helper = Path(__file__).with_name("capture_helper.py")
            process = subprocess.Popen([sys.executable, str(helper), str(executable), directory],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), "started")
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(marker.exists())
                process.stdin.close()
                self.assertEqual(process.wait(timeout=6), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()

    def test_helper_passes_spoof_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "capture"
            executable.write_text("#!/usr/bin/env python3\nimport json, pathlib, sys\npathlib.Path('args').write_text(json.dumps(sys.argv[1:]))\n", encoding="utf-8")
            os.chmod(executable, 0o755)
            helper = Path(__file__).with_name("capture_helper.py")
            process = subprocess.Popen([sys.executable, str(helper), str(executable), directory, "192.0.2.2", "192.0.2.1", "192.0.2.3"],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None: process.kill(); process.wait()
                process.stdin.close()
                process.stderr.close()
            self.assertEqual(json.loads((Path(directory) / "args").read_text()),
                             ["--packet-json", "--spoof", "192.0.2.2", "192.0.2.1", "192.0.2.3"])


if __name__ == "__main__":
    unittest.main()
