#!/usr/bin/env python3
"""
Finding 014: negative lpf indent writes before the line buffer.
"""

from __future__ import annotations

from common import OOBWrite, Result, assert_true, run_poc


def lpf_write_old(indent: int, ch: str, width: int = 132) -> int:
    col = indent
    if col >= width or ord(ch) < 32:
        return col + 1
    if col < 0:
        raise OOBWrite("write before buf[0]")
    return col


def lpf_write_patched(indent: int, ch: str, width: int = 132) -> int:
    return lpf_write_old(max(indent, 0), ch, width)


def poc() -> Result:
    try:
        lpf_write_old(-100000, "A")
    except OOBWrite:
        old_oob = True
    else:
        old_oob = False
    patched_col = lpf_write_patched(-100000, "A")
    assert_true(old_oob, "old lpf model did not write before line buffer")
    assert_true(patched_col == 0, "patched lpf did not clamp negative indent")
    return Result("014", "Negative lpf indent writes before buffer",
                  "-i-100000 makes first printable byte target buf[0][-100000] in the old path")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

