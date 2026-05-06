#!/usr/bin/env python3
"""
Finding 006: wildcard source block is bypassed.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def mta_block_key(source: str, domain: str | None) -> tuple[str, str | None]:
    return source, domain


def mta_is_blocked_old(blocks: set[tuple[str, str | None]], source: str, domain: str | None) -> bool:
    return mta_block_key(source, domain) in blocks


def mta_is_blocked_patched(blocks: set[tuple[str, str | None]], source: str, domain: str | None) -> bool:
    return mta_block_key(source, domain) in blocks or (domain is not None and mta_block_key(source, None) in blocks)


def poc() -> Result:
    blocks = {mta_block_key("198.51.100.9", None)}
    assert_true(not mta_is_blocked_old(blocks, "198.51.100.9", "example.com"),
                "old exact lookup unexpectedly matched wildcard source block")
    assert_true(mta_is_blocked_patched(blocks, "198.51.100.9", "example.com"),
                "patched lookup did not apply wildcard source block")
    return Result("006", "Wildcard MTA source block bypass",
                  "source/* block does not stop source/example.com delivery in the old exact-lookup path")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

