#!/usr/bin/env python3
"""
Finding 009: malformed FastCGI header bypasses HTTP response framing.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def fcgi_getheaders_old(buffer: bytes) -> tuple[bool, bytes]:
    rest = buffer
    while True:
        if b"\n" not in rest:
            return False, rest
        line, rest = rest.split(b"\n", 1)
        line = line.rstrip(b"\r")
        if line == b"":
            return True, rest
        if b":" not in line:
            return False, rest


def fcgi_getheaders_patched(buffer: bytes) -> tuple[int, bytes]:
    rest = buffer
    while True:
        if b"\n" not in rest:
            return 0, rest
        line, rest = rest.split(b"\n", 1)
        line = line.rstrip(b"\r")
        if line == b"":
            return 1, rest
        if b":" not in line:
            return -1, rest


def poc() -> Result:
    payload = b"not-a-header\r\nHTTP/1.1 200 OK\r\nX-Evil: yes\r\n\r\nbody"
    headersdone, rest = fcgi_getheaders_old(payload)
    patched_ret, patched_rest = fcgi_getheaders_patched(payload)
    old_forwarded = rest if not headersdone else b""
    assert_true(old_forwarded.startswith(b"HTTP/1.1 200 OK"),
                "old FastCGI path did not leave raw HTTP bytes to forward")
    assert_true(patched_ret == -1 and patched_rest.startswith(b"HTTP/1.1 200 OK"),
                "patched parser did not reject malformed colonless header")
    return Result("009", "Malformed FastCGI header bypasses HTTP framing",
                  "colonless line is consumed and raw 'HTTP/1.1 200 OK' remains buffered in old path")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

