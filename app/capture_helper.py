"""Privileged capture supervisor: stdin EOF requests a clean shutdown."""
import os
import ipaddress
import select
import signal
import subprocess
import sys


def main():
    if len(sys.argv) != 3 and len(sys.argv) < 5:
        return 2
    args = [sys.argv[1], "--packet-json"]
    if len(sys.argv) >= 5:
        try:
            target, gateway, *more = (str(ipaddress.IPv4Address(value)) for value in sys.argv[3:])
        except ipaddress.AddressValueError:
            print("Invalid target or gateway IPv4 address", file=sys.stderr)
            return 2
        targets = [target, *more]
        if gateway in targets or len(set(targets)) != len(targets) or len(targets) > 64:
            print("Targets must be unique, different from the gateway, and at most 64", file=sys.stderr)
            return 2
        args += ["--spoof", target, gateway, *more]
    os.chdir(sys.argv[2])
    os.umask(0o022)  # The containing directory is private to the desktop user.
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=sys.stderr)
    print("started", flush=True)
    try:
        while child.poll() is None:
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if ready and not os.read(sys.stdin.fileno(), 1024):
                break
    finally:
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            child.wait()
    return child.returncode


if __name__ == "__main__":
    sys.exit(main())
