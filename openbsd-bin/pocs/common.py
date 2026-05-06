#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass


class OOBRead(Exception):
    pass


class OOBWrite(Exception):
    pass


class PoCFailure(AssertionError):
    pass


@dataclass(frozen=True)
class Result:
    finding: str
    title: str
    detail: str


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise PoCFailure(message)


def print_result(result: Result) -> None:
    print(f"[PASS] {result.finding} {result.title}")
    print(f"       {result.detail}")


def run_poc(poc) -> int:
    try:
        print_result(poc())
    except Exception as exc:  # pragma: no cover - command-line reporting
        name = getattr(poc, "__name__", "poc")
        print(f"[FAIL] {name}: {exc}")
        return 1
    return 0


def strlcpy(dst: str, src: str, size: int) -> tuple[str, int]:
    if size == 0:
        return "", len(src)
    return src[: size - 1], len(src)


def strlcat(dst: str, src: str, size: int) -> tuple[str, int]:
    wanted = len(dst) + len(src)
    if len(dst) >= size:
        return dst, wanted
    return dst + src[: max(0, size - len(dst) - 1)], wanted

