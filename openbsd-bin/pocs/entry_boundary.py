#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass

from common import OOBRead, OOBWrite, Result, assert_true


@dataclass(frozen=True)
class EntryCheckCase:
    finding: str
    title: str
    entry_size: int
    ndx: int
    data_size: int
    operation: str


def start_only_check(msz: int, ndx: int, d_size: int) -> bool:
    return msz * ndx < d_size


def read_full_entry(msz: int, ndx: int, d_size: int) -> None:
    start = msz * ndx
    if start + msz > d_size:
        raise OOBRead(f"read [{start}, {start + msz}) crosses d_size {d_size}")


def write_full_entry(msz: int, ndx: int, d_size: int) -> None:
    start = msz * ndx
    if start + msz > d_size:
        raise OOBWrite(f"write [{start}, {start + msz}) crosses d_size {d_size}")


def patched_read_check(msz: int, ndx: int, d_size: int) -> bool:
    return ndx < d_size // msz


def patched_write_check_subtract(msz: int, ndx: int, d_size: int) -> bool:
    return d_size >= msz and ndx <= (d_size - msz) // msz


def poc_entry_boundary(case: EntryCheckCase) -> Result:
    old_accepts = start_only_check(case.entry_size, case.ndx, case.data_size)
    if case.operation == "read":
        try:
            read_full_entry(case.entry_size, case.ndx, case.data_size)
        except OOBRead:
            old_oob = True
        else:
            old_oob = False
        patched_accepts = patched_read_check(case.entry_size, case.ndx, case.data_size)
    else:
        try:
            write_full_entry(case.entry_size, case.ndx, case.data_size)
        except OOBWrite:
            old_oob = True
        else:
            old_oob = False
        patched_accepts = patched_write_check_subtract(case.entry_size, case.ndx, case.data_size)
    assert_true(old_accepts and old_oob,
                f"old {case.operation} boundary model did not accept then cross d_size")
    assert_true(not patched_accepts,
                f"patched {case.operation} check accepted truncated entry")
    start = case.entry_size * case.ndx
    return Result(case.finding, case.title,
                  f"d_size={case.data_size}, msz={case.entry_size}, ndx={case.ndx}: start {start} is in bounds but full entry crosses end")

