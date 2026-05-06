#!/usr/bin/env python3
"""
Finding 011: certificate verifier ignores CRL file.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def ca_verify_old(chain_ok: bool, revoked_in_crl: bool, crlfile_supplied: bool) -> bool:
    return chain_ok


def ca_verify_patched(chain_ok: bool, revoked_in_crl: bool, crlfile_supplied: bool) -> bool:
    return chain_ok and not (crlfile_supplied and revoked_in_crl)


def poc() -> Result:
    assert_true(ca_verify_old(True, True, True), "old CA verifier did not ignore CRLfile")
    assert_true(not ca_verify_patched(True, True, True), "patched CA verifier did not reject revoked cert")
    return Result("011", "Certificate verifier ignores CRL file",
                  "revoked-but-chain-valid peer verifies when CRLfile is accepted but not loaded")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

