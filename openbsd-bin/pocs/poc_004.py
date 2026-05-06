#!/usr/bin/env python3
"""
Finding 004: pipelining clears PASV rewrite state.
"""

from __future__ import annotations

from dataclasses import dataclass

from common import Result, assert_true, run_poc


@dataclass
class Session:
    cmd: str = "NONE"
    port: int = 0
    fixed_server: bool = True
    orig_server: str = "203.0.113.10"
    backend_server: str = "10.0.0.5"


def ftp_client_parse_old(session: Session, line: str) -> None:
    session.cmd = "NONE"
    session.port = 0
    ftp_client_parse_cmd(session, line)


def ftp_client_parse_patched(session: Session, line: str) -> None:
    ftp_client_parse_cmd(session, line)


def ftp_client_parse_cmd(session: Session, line: str) -> None:
    cmd = line[:4].upper()
    if cmd == "PASV":
        session.cmd = "PASV"
    elif cmd == "EPSV":
        session.cmd = "EPSV"


def ftp_server_parse(session: Session, line: str) -> str:
    if session.cmd == "PASV" and line.startswith("227 "):
        session.cmd = "NONE"
        return line.replace(session.backend_server.replace(".", ","), session.orig_server.replace(".", ","))
    session.cmd = "NONE"
    return line


def poc() -> Result:
    backend_227 = "227 Entering Passive Mode (10,0,0,5,195,80)"
    old = Session()
    ftp_client_parse_old(old, "PASV")
    ftp_client_parse_old(old, "NOOP")
    old_reply = ftp_server_parse(old, backend_227)
    patched = Session()
    ftp_client_parse_patched(patched, "PASV")
    ftp_client_parse_patched(patched, "NOOP")
    patched_reply = ftp_server_parse(patched, backend_227)
    assert_true("10,0,0,5" in old_reply, "old proxy rewrote reply despite pipelined state clear")
    assert_true("203,0,113,10" in patched_reply, "patched proxy did not preserve PASV rewrite state")
    return Result("004", "Pipelined FTP command clears PASV rewrite state",
                  "PASV;NOOP before 227 leaks backend passive address 10.0.0.5 in the old flow")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

