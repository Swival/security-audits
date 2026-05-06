#!/usr/bin/env python3
"""
Finding 010: OCSP UNKNOWN status is accepted.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def ocsp_verify_old(status: str) -> bool:
    return status in {"GOOD", "UNKNOWN"}


def ocsp_verify_patched(status: str) -> bool:
    return status == "GOOD"


def poc() -> Result:
    assert_true(ocsp_verify_old("UNKNOWN"), "old OCSP verifier did not accept UNKNOWN")
    assert_true(not ocsp_verify_patched("UNKNOWN"), "patched OCSP verifier accepted UNKNOWN")
    return Result("010", "OCSP UNKNOWN status accepted",
                  "signed/fresh/matching UNKNOWN response reaches success in the old final status gate")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

