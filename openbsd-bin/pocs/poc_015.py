#!/usr/bin/env python3
"""
Finding 015: control-file hostname rewrite writes past command buffer.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc

BUFSIZ = 1024


def recvjob_rewrite_old(cp_offset: int, fromhost: str) -> tuple[int, int]:
    dest = cp_offset + 6
    length = (BUFSIZ - cp_offset - 6) % (1 << 64)
    return dest, length


def recvjob_rewrite_patched(cp: str, cp_offset: int, fromhost: str) -> bool:
    remaining = BUFSIZ - cp_offset - 6
    if len(cp) < 6 or remaining <= 0 or len(fromhost) >= remaining:
        return False
    return True


def poc() -> Result:
    cp_offset = BUFSIZ - 5
    dest, length = recvjob_rewrite_old(cp_offset, "remotehost")
    patched_ok = recvjob_rewrite_patched("cf", cp_offset, "remotehost")
    assert_true(dest > BUFSIZ and length > BUFSIZ,
                "old recvjob rewrite did not compute out-of-buffer destination/huge length")
    assert_true(not patched_ok, "patched recvjob guard did not reject short late filename")
    return Result("015", "LPD recvjob hostname rewrite writes past line[]",
                  f"cp at BUFSIZ-5 makes cp+6={dest} and copy length wrap to {length}")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

