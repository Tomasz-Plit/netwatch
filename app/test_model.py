import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from model import CaptureModel, JsonLines, category_for, default_interface
from main import graph_scale, handshake_text


class ModelTests(unittest.TestCase):
    def test_graph_scale_rounds_up_and_handles_no_traffic(self):
        self.assertEqual(graph_scale(0), 1000)
        self.assertEqual(graph_scale(1234), 2000)
        self.assertEqual(graph_scale(5000), 5000)

    def test_handshake_details_include_both_sides_or_missing_message(self):
        item = {"key": ("a", 1234, "b", 443), "client": {"sni": "example.com", "alpn": ["h2"]},
                "server": {"version": "0x0304", "cipher": "0x1301"}}
        text = handshake_text(item)
        self.assertIn("Hostname: example.com", text)
        self.assertIn("Protocols: h2", text)
        self.assertIn("Selected cipher: 0x1301", text)
        item["server"] = None
        self.assertIn("SERVER HELLO  ·  Not captured", handshake_text(item))

    def test_categories_match_domain_boundaries(self):
        self.assertEqual(category_for("WWW.YouTube.com."), "Video")
        self.assertEqual(category_for("notyoutube.com"), "Other")
        self.assertEqual(category_for("unknown.example"), "Other")

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
        self.assertEqual(model.categories["Video"], 1)
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


if __name__ == "__main__":
    unittest.main()
