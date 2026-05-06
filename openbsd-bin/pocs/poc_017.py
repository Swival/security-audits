#!/usr/bin/env python3
"""
Finding 017: trailing-dot wildcard matches a top-level domain.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def tls_match_name_old(cert_name: str, name: str) -> bool:
    if cert_name.startswith("*."):
        cert_domain = cert_name[1:]
        domain_pos = name.find(".")
        if domain_pos == -1:
            return False
        if cert_domain.startswith(".."):
            return False
        next_dot = cert_domain[1:].find(".")
        if next_dot == -1:
            return False
        next_dot_index = next_dot + 1
        if next_dot_index + 1 < len(cert_domain) and cert_domain[next_dot_index + 1] == ".":
            return False
        return cert_domain.lower() == name[domain_pos:].lower()
    return cert_name.lower() == name.lower()


def tls_match_name_patched(cert_name: str, name: str) -> bool:
    if cert_name.startswith("*."):
        cert_domain = cert_name[1:]
        next_dot = cert_domain[1:].find(".")
        if next_dot == -1:
            return False
        next_dot_index = next_dot + 1
        if next_dot_index + 1 == len(cert_domain):
            return False
    return tls_match_name_old(cert_name, name)


def poc() -> Result:
    assert_true(tls_match_name_old("*.com.", "victim.com."),
                "old TLS name matcher did not accept trailing-dot TLD wildcard")
    assert_true(not tls_match_name_old("*.com", "victim.com"),
                "control case *.com should already be rejected")
    assert_true(not tls_match_name_patched("*.com.", "victim.com."),
                "patched TLS name matcher accepted trailing-dot TLD wildcard")
    return Result("017", "Trailing-dot wildcard matches top-level domain",
                  "old tls_match_name accepts *.com. for victim.com. but rejects *.com for victim.com")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

