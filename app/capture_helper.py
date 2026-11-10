"""Privileged capture supervisor: stdin EOF requests a clean shutdown."""
import os
import select
import signal
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        return 2
    os.chdir(sys.argv[2])
    os.umask(0o022)  # The containing directory is private to the desktop user.
    child = subprocess.Popen([sys.argv[1]], stdin=subprocess.DEVNULL,
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
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    return child.returncode


if __name__ == "__main__":
    sys.exit(main())
