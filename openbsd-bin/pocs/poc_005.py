#!/usr/bin/env python3
"""
Finding 005: envelope fields leak on every delivery.
"""

from __future__ import annotations

from common import Result, assert_true, run_poc


class LeakTracker:
    def __init__(self) -> None:
        self.live: set[int] = set()
        self.next_id = 1

    def xstrdup(self, value: str | None) -> int | None:
        if value is None:
            return None
        ident = self.next_id
        self.next_id += 1
        self.live.add(ident)
        return ident

    def free(self, ident: int | None) -> None:
        if ident is not None:
            self.live.discard(ident)


def mda_cycle(tracker: LeakTracker, patched: bool, subaddress: bool) -> None:
    envelope = {
        "sender": tracker.xstrdup("sender@example"),
        "dest": tracker.xstrdup("dest"),
        "rcpt": tracker.xstrdup("rcpt"),
        "user": tracker.xstrdup("user"),
        "mda_exec": tracker.xstrdup("/bin/mail"),
        "dispatcher": tracker.xstrdup("local"),
        "mda_subaddress": tracker.xstrdup("tag") if subaddress else None,
    }
    for key in ["sender", "dest", "rcpt", "user", "mda_exec"]:
        tracker.free(envelope[key])
    if patched:
        tracker.free(envelope["dispatcher"])
        tracker.free(envelope["mda_subaddress"])


def poc() -> Result:
    old_tracker = LeakTracker()
    patched_tracker = LeakTracker()
    for _ in range(10):
        mda_cycle(old_tracker, patched=False, subaddress=True)
        mda_cycle(patched_tracker, patched=True, subaddress=True)
    assert_true(len(old_tracker.live) == 20, "old destructor did not leak dispatcher/subaddress allocations")
    assert_true(len(patched_tracker.live) == 0, "patched destructor still leaks allocations")
    return Result("005", "MDA envelope leaks dispatcher and subaddress",
                  "10 deliveries leave 20 heap allocations live in the old destructor model")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

