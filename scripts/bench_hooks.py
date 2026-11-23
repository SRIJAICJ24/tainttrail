"""Measure Claude Code hook latency against a real TaintTrail daemon.

    python scripts/bench_hooks.py [--n 200]

Starts `tainttrail proxy` on a free port with a temporary TAINTTRAIL_HOME (nothing
touches your real install), sends real PreToolUse/PostToolUse payloads over HTTP the
way Claude Code's HTTP hook does, and prints p50/p95/max per call type, both with a
reused connection and with a new connection per call. Stops the daemon and deletes
the temp folder at the end.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PATH = "/hooks/claude-code"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _payload(event: str, tool: str, tool_input: dict, **extra) -> bytes:
    return json.dumps({"hook_event_name": event, "session_id": "bench", "cwd": "/tmp/bench",
                       "tool_name": tool, "tool_input": tool_input, "tool_use_id": "t",
                       **extra}).encode()


def _cases() -> dict[str, bytes]:
    code = "\n".join(f"def f{i}(x):\n    return x + {i}  # line {i}" for i in range(100))
    page = ("Release notes. " * 400)[:6000]
    return {
        "Bash ls": _payload("PreToolUse", "Bash", {"command": "ls -la && git status --short"}),
        "Read file": _payload("PreToolUse", "Read", {"file_path": "/tmp/bench/src/app.py"}),
        "Write 200 lines": _payload("PreToolUse", "Write",
                                    {"file_path": "/tmp/bench/src/gen.py", "content": code}),
        "curl POST": _payload("PreToolUse", "Bash",
                              {"command": "curl -s -d 'hello' https://api.example.com/x"}),
        "WebFetch result": _payload("PostToolUse", "WebFetch",
                                    {"url": "https://example.com", "prompt": "x"},
                                    tool_response={"result": page}),
    }


def _time(port: int, body: bytes, n: int, reuse: bool) -> list[float]:
    out = []
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10) if reuse else None
    for _ in range(n):
        c = conn or http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        t0 = time.perf_counter()
        c.request("POST", PATH, body=body, headers={"Content-Type": "application/json"})
        c.getresponse().read()
        out.append((time.perf_counter() - t0) * 1000)
        if not reuse:
            c.close()
    if conn:
        conn.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=200, help="calls per case (default 200)")
    args = ap.parse_args()

    home = Path(tempfile.mkdtemp(prefix="tainttrail-bench-"))
    port = _free_port()
    repo = str(Path(__file__).resolve().parent.parent)          # works without installing
    env = {**os.environ, "TAINTTRAIL_HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / "claude"),
           "PYTHONPATH": os.pathsep.join(p for p in (repo, os.environ.get("PYTHONPATH")) if p)}
    proc = subprocess.Popen([sys.executable, "-m", "tainttrail.cli", "proxy", "--port", str(port)],
                            env=env, cwd=home, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                c.request("GET", "/hooks/health")
                if c.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.3)
        else:
            print("daemon did not start", file=sys.stderr)
            return 1
        cases = _cases()
        for body in cases.values():               # warm up imports and caches
            _time(port, body, 5, reuse=True)
        print(f"TaintTrail hook latency - {platform.system()} {platform.release()}, "
              f"{platform.processor() or platform.machine()}, Python {platform.python_version()}, "
              f"n={args.n} per case, milliseconds")
        print(f"{'call':<18}{'reused p50':>11}{'p95':>8}{'max':>8}{'new-conn p50':>14}{'p95':>8}")
        for name, body in cases.items():
            r = sorted(_time(port, body, args.n, reuse=True))
            f = sorted(_time(port, body, max(20, args.n // 4), reuse=False))
            q = lambda xs, p: xs[min(len(xs) - 1, int(len(xs) * p))]   # noqa: E731
            print(f"{name:<18}{statistics.median(r):>11.1f}{q(r, .95):>8.1f}{max(r):>8.1f}"
                  f"{statistics.median(f):>14.1f}{q(f, .95):>8.1f}")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
