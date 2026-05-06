#!/usr/bin/env python3
"""
Finding 001: full Basic auth credential buffer is scanned past its end.
"""

from __future__ import annotations

import base64

from common import OOBRead, Result, assert_true, run_poc


def c_strchr_scan(buffer: bytes, target: int) -> int:
    """Simulate strchr() over a fixed object and raise when it leaves it."""
    for i, b in enumerate(buffer):
        if b == target:
            return i
        if b == 0:
            return -1
    raise OOBRead("strchr scanned past the decoded[1024] stack object")


def poc() -> Result:
    decoded_payload = b"A" * 1024
    header = base64.b64encode(decoded_payload)
    decoded = base64.b64decode(header)
    assert_true(len(decoded) == 1024 and b":" not in decoded and b"\0" not in decoded,
                "trigger must decode to a full unterminated colon-free buffer")
    try:
        c_strchr_scan(decoded, ord(":"))
    except OOBRead:
        vulnerable = True
    else:
        vulnerable = False
    patched_decoded = decoded[:1023] + b"\0"
    patched_result = c_strchr_scan(patched_decoded, ord(":"))
    assert_true(vulnerable, "old Basic auth path did not overread")
    assert_true(patched_result == -1, "patched reserved NUL byte did not stop scan")
    return Result("001", "Basic auth full decoded buffer overread",
                  f"{len(header)} byte Basic token decodes to 1024 non-NUL bytes and drives strchr past decoded[]")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

