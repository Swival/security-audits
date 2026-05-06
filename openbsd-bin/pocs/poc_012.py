#!/usr/bin/env python3
"""
Finding 012: unbounded LMTP reply line allocation.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def lmtp_getline_old(stream: bytes) -> int:
    # getline() allocates until newline or EOF before syntax validation.
    return len(stream.split(b"\n", 1)[0])


def lmtp_read_patched(stream: bytes, limit: int = 512) -> bool:
    first_chunk = stream[:limit]
    return b"\n" in first_chunk or len(first_chunk) < limit


def poc() -> Result:
    line = b"220 " + b"A" * (1024 * 1024)
    allocated = lmtp_getline_old(line)
    patched_ok = lmtp_read_patched(line)
    assert_true(allocated > 512, "old getline model did not allocate overlong line")
    assert_true(not patched_ok, "patched bounded LMTP reader did not reject overlong line")
    return Result("012", "Unbounded LMTP reply line allocation",
                  f"newline-free banner forces getline-sized allocation of {allocated} bytes before validation")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

