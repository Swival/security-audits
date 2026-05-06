#!/usr/bin/env python3
"""
Finding 008: print job fields inject mail recipients.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def lpd_sendmail_header_old(user: str, fromhost: str) -> str | None:
    if user[0] in "-/" or not user[0].isprintable():
        return None
    return f"To: {user}@{fromhost}\n"


def safe_atom(value: str, allow_underscore: bool) -> bool:
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.")
    if allow_underscore:
        allowed.add("_")
    return bool(value) and all(ch in allowed for ch in value)


def lpd_sendmail_header_patched(user: str, fromhost: str) -> str | None:
    if user.startswith(("-", "/")) or not safe_atom(user, True) or not safe_atom(fromhost, False):
        return None
    return f"To: {user}@{fromhost}\n"


def parse_sendmail_t_recipients(header: str) -> list[str]:
    return [part.strip() for part in header.removeprefix("To:").split(",")]


def poc() -> Result:
    header = lpd_sendmail_header_old("daemon", "client.example,victim@example.net")
    patched = lpd_sendmail_header_patched("daemon", "client.example,victim@example.net")
    assert_true(header is not None and "victim@example.net" in parse_sendmail_t_recipients(header),
                "old sendmail header did not contain injected recipient")
    assert_true(patched is None, "patched validation did not reject comma in fromhost")
    return Result("008", "LPD control fields inject mail recipients",
                  header.strip())


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

