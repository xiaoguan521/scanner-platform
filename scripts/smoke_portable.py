#!/usr/bin/env python3
"""Smoke-test an unpacked sec-portable package on loopback; never scans.

Checks that the package has the expected layout, that --status reports the
embedded UI (and engines unless --allow-missing-engines), that the program
starts on 127.0.0.1, serves the embedded UI, refuses node API calls without
this run's token, refuses a second copy on the same directory, and stops.
The package directory is copied to a temporary home first, so the original
stays untouched.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REQUIRED = ["bin", "vuln-data", "config", "README.md"]


def executable(home):
    name = "sec-portable.exe" if os.name == "nt" else "sec-portable"
    return os.path.join(home, name)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def check(condition, message):
    if not condition:
        raise SystemExit("smoke test failed: " + message)
    print("ok:", message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="unpacked package directory")
    parser.add_argument("--allow-missing-engines", action="store_true", help="for local builds without bin/ engines")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()

    source = os.path.abspath(args.package)
    for entry in REQUIRED:
        check(os.path.exists(os.path.join(source, entry)), f"package contains {entry}")
    check(os.path.isfile(executable(source)), "package contains the sec-portable program")

    with tempfile.TemporaryDirectory(prefix="sec-portable-smoke-", ignore_cleanup_errors=True) as temporary:  # Windows may still hold bin/*.exe briefly after the process exits
        home = os.path.join(temporary, "sec-portable")
        shutil.copytree(source, home, symlinks=True)
        program = executable(home)

        status = json.loads(subprocess.run([program, "--status"], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30).stdout)
        check(status.get("mode") == "portable" and status.get("embeddedUI") is True, "--status reports the embedded web UI")
        check(status.get("networkFence") is False, "--status reports that no network fence is used")
        if not args.allow_missing_engines:
            check(status.get("engines") == {"nuclei": True, "trivy": True}, "--status finds nuclei and trivy in bin/")
        check(not os.path.exists(os.path.join(home, "runtime", "platform.db")), "--status created no database")

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
        process = subprocess.Popen([program, "--listen", f"127.0.0.1:{port}", "--no-browser"], cwd=temporary,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", **flags)
        try:
            deadline = time.time() + args.timeout
            while True:
                try:
                    code, body = request(base + "/readyz")
                    if code == 200:
                        break
                except OSError:
                    pass
                if process.poll() is not None or time.time() > deadline:
                    output = process.stdout.read() if process.stdout else ""
                    raise SystemExit("smoke test failed: sec-portable did not become ready\n" + output)
                time.sleep(0.3)
            check(True, "sec-portable answers /readyz on 127.0.0.1")
            code, body = request(base + "/")
            check(code == 200 and "<html" in body.lower(), "embedded web UI is served")
            code, _ = request(base + "/api/v1/worker/claim", method="POST", data=b"{}",
                              headers={"X-Node-ID": "portable-worker", "Authorization": "Bearer guessed", "Content-Type": "application/json"})
            check(code == 401, "node API refuses a request without this run's token")
            second = subprocess.run([program, "--listen", f"127.0.0.1:{free_port()}", "--no-browser"],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            check(second.returncode != 0 and "already" in second.stderr, "a second copy on the same directory is refused")
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    process.terminate()
                else:
                    process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    raise SystemExit("smoke test failed: sec-portable did not stop")
        output = process.stdout.read() if process.stdout else ""
        if os.name != "nt":
            check(process.returncode == 0, f"sec-portable stops cleanly on Ctrl+C (exit {process.returncode})\n{output[-2000:] if process.returncode else ''}")
        check(os.path.isfile(os.path.join(home, "runtime", "logs", "portable.log")), "runtime log was written")
    print("sec-portable package smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
