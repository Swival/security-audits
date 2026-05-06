#!/usr/bin/env python3
"""
Finding 002: failed Basic auth attempts spoof remote user in logs.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


def authenticate_old(user: str, password_ok: bool) -> tuple[int, str | None]:
    remote_user = user
    return (0 if password_ok else -1), remote_user


def authenticate_patched(user: str, password_ok: bool) -> tuple[int, str | None]:
    remote_user = user if password_ok else None
    return (0 if password_ok else -1), remote_user


def log_remote_user(remote_user: str | None) -> str:
    return remote_user if remote_user is not None else "-"


def poc() -> Result:
    status, old_user = authenticate_old("root", False)
    patched_status, patched_user = authenticate_patched("root", False)
    assert_true(status == -1 and log_remote_user(old_user) == "root",
                "old failed authentication did not log attacker-selected user")
    assert_true(patched_status == -1 and log_remote_user(patched_user) == "-",
                "patched failed authentication still populates remote user")
    return Result("002", "Failed Basic auth spoofs access-log remote user",
                  "bad credentials for user 'root' produce a 401 log entry attributed to root in the old flow")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

