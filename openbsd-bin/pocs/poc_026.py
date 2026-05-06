#!/usr/bin/env python3
"""
Finding 026: BSD __.SYMDEF arraysize check allows an out-of-bounds read.
"""

from __future__ import annotations

import struct

from common import OOBRead, Result, assert_true, run_poc

LONG_SIZE = struct.calcsize("l")


def poc() -> Result:
    entrysize = 2 * LONG_SIZE
    rawsymtabsz = LONG_SIZE + entrysize
    arraysize = rawsymtabsz - LONG_SIZE
    # Old check uses p0 + arraysize >= end, after GET_LONG has already advanced p.
    p0 = 0
    p = LONG_SIZE
    end = rawsymtabsz
    old_check_passes = arraysize >= 0 and p0 + arraysize < end and arraysize % entrysize == 0
    s = p + arraysize
    try:
        if s + LONG_SIZE > end:
            raise OOBRead("GET_LONG(s, strtabsize) starts at or beyond end")
    except OOBRead:
        old_oob = True
    else:
        old_oob = False
    patched_rejects = p + arraysize + LONG_SIZE > end
    assert_true(old_check_passes and s == end and old_oob,
                "old BSD symtab arraysize check did not permit GET_LONG at end")
    assert_true(patched_rejects, "patched BSD symtab check did not reject missing strtabsize")
    return Result("026", "BSD __.SYMDEF arraysize check allows OOB read",
                  f"arraysize={arraysize} passes old p0 check, then strtabsize read starts at end offset {s}")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

