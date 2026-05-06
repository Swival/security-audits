#!/usr/bin/env python3
"""
Finding 003: long argv hides executed arguments from the audit log.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc, strlcat, strlcpy

LINE_MAX = 2048


def doas_log_old(argv: list[str]) -> str:
    cmdline, _ = strlcpy("", argv[0], LINE_MAX)
    for arg in argv[1:]:
        cmdline, wanted = strlcat(cmdline, " ", LINE_MAX)
        if wanted >= LINE_MAX:
            break
        cmdline, wanted = strlcat(cmdline, arg, LINE_MAX)
        if wanted >= LINE_MAX:
            break
    return cmdline


def doas_log_patched(argv: list[str]) -> str:
    cmdline, wanted = strlcpy("", argv[0], LINE_MAX)
    if wanted >= LINE_MAX:
        raise ValueError("command line too long")
    for arg in argv[1:]:
        cmdline, wanted = strlcat(cmdline, " ", LINE_MAX)
        if wanted >= LINE_MAX:
            raise ValueError("command line too long")
        cmdline, wanted = strlcat(cmdline, arg, LINE_MAX)
        if wanted >= LINE_MAX:
            raise ValueError("command line too long")
    return cmdline


def poc() -> Result:
    hidden = "--security-relevant"
    argv = ["/bin/echo", "A" * (LINE_MAX + 32), hidden]
    old_log = doas_log_old(argv)
    old_exec = " ".join(argv)
    try:
        doas_log_patched(argv)
    except ValueError:
        patched_rejects = True
    else:
        patched_rejects = False
    assert_true(hidden not in old_log and hidden in old_exec,
                "old doas log did not diverge from executed argv")
    assert_true(patched_rejects, "patched doas did not reject truncated command line")
    return Result("003", "doas logs truncated argv but executes full argv",
                  f"audit string length {len(old_log)} omits trailing {hidden!r} that remains in exec argv")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

