import queue
import unittest
from unittest.mock import MagicMock

from main import Dashboard


class ErrorReportingTests(unittest.TestCase):
    def dashboard(self):
        dashboard = MagicMock()
        dashboard.messages = queue.Queue()
        dashboard.scan_messages = queue.Queue()
        dashboard.packet_reader.read.return_value = []
        dashboard.reader.read.return_value = []
        dashboard.capture_error_reported = False
        return dashboard

    def test_failed_capture_shows_error_once(self):
        dashboard = self.dashboard()
        dashboard.process.poll.return_value = 1
        dashboard.process.returncode = 1
        dashboard.last_error = "permission denied"
        Dashboard.tick(dashboard)
        dashboard.show_error.assert_called_once_with(
            "Capture stopped unexpectedly", "Exit code: 1\n\npermission denied")
        Dashboard.tick(dashboard)
        dashboard.show_error.assert_called_once()

    def test_scan_failure_is_shown_even_when_discovery_is_closed(self):
        dashboard = self.dashboard()
        dashboard.process = None
        dashboard.discovery_window = None
        dashboard.scan_messages.put((1, "", "scan failed", "eth0", "192.0.2.1", None))
        Dashboard.tick(dashboard)
        dashboard.show_error.assert_called_once_with("Network scan failed", "scan failed", None)

    def test_read_error_is_not_repeated_while_stopping(self):
        dashboard = self.dashboard()
        dashboard.packet_reader.read.side_effect = OSError("disk error")
        Dashboard.tick(dashboard)
        Dashboard.tick(dashboard)
        dashboard.show_error.assert_called_once_with("Cannot read capture data", "disk error")


if __name__ == "__main__":
    unittest.main()
