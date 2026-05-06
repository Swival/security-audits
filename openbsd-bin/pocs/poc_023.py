#!/usr/bin/env python3
from __future__ import annotations

from common import run_poc
from entry_boundary import EntryCheckCase, poc_entry_boundary


def poc():
    return poc_entry_boundary(EntryCheckCase("023", "Truncated RELA update writes past buffer", 24, 0, 1, "write"))


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

