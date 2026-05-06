#!/usr/bin/env python3
"""
Finding 013: BSD extended archive name overreads backing buffer.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc

AR_HDR_SIZE = 60


def ar_get_name_old(raw: bytes, rawsize: int, name_len: int) -> bytes:
    q = AR_HDR_SIZE
    # strncpy() reads name_len bytes regardless of rawsize.
    return raw[q : q + name_len]


def ar_get_name_patched(raw: bytes, rawsize: int, name_len: int) -> bytes | None:
    q = AR_HDR_SIZE
    if q > rawsize or name_len > rawsize - q:
        return None
    return raw[q : q + name_len]


def poc() -> Result:
    rawsize = AR_HDR_SIZE
    raw = b"H" * AR_HDR_SIZE + b"LEAKED_SECRET_BYTES!"
    old_name = ar_get_name_old(raw, rawsize, 20)
    patched_name = ar_get_name_patched(raw, rawsize, 20)
    assert_true(old_name.startswith(b"LEAKED_SECRET"), "old archive name copy did not read beyond rawsize")
    assert_true(patched_name is None, "patched archive name check did not reject missing payload")
    return Result("013", "BSD extended archive name overreads backing buffer",
                  f"#1/20 header ending at rawsize returns adjacent bytes {old_name!r}")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

