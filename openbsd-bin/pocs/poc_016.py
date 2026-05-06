#!/usr/bin/env python3
"""
Finding 016: UDP payload may extend past the IPv4 packet.
"""

from __future__ import annotations

import ipaddress
import struct

from common import Result, assert_true, run_poc


def ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\0"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_smuggled_udp_frame() -> tuple[bytes, int, int, int]:
    offset = 14
    ihl = 20
    udp_len = 8 + 240
    ip_total = ihl + 8
    eth = b"\0" * offset
    ip_no_sum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, 0, 0, 64, 17, 0,
                            ipaddress.IPv4Address("192.0.2.1").packed,
                            ipaddress.IPv4Address("192.0.2.2").packed)
    csum = ipv4_checksum(ip_no_sum)
    ip = ip_no_sum[:10] + struct.pack("!H", csum) + ip_no_sum[12:]
    udp = struct.pack("!HHHH", 68, 67, udp_len, 0)
    trailing_dhcp = b"\x01" + b"D" * 239
    frame = eth + ip + udp + trailing_dhcp
    return frame, offset, ihl, ip_total


def decode_udp_old(buflen: int, offset: int, ihl: int, ip_total: int, udp_len: int) -> bool:
    if buflen < offset + ip_total:
        return False
    if buflen < offset + ihl + 8:
        return False
    if buflen < offset + ihl + udp_len:
        return False
    return True


def decode_udp_patched(buflen: int, offset: int, ihl: int, ip_total: int, udp_len: int) -> bool:
    if buflen < offset + ip_total:
        return False
    if ip_total < ihl + 8:
        return False
    if ip_total < ihl + udp_len:
        return False
    return True


def poc() -> Result:
    frame, offset, ihl, ip_total = make_smuggled_udp_frame()
    udp_len = struct.unpack("!H", frame[offset + ihl + 4 : offset + ihl + 6])[0]
    assert_true(decode_udp_old(len(frame), offset, ihl, ip_total, udp_len),
                "old UDP decoder rejected trailing capture bytes")
    assert_true(not decode_udp_patched(len(frame), offset, ihl, ip_total, udp_len),
                "patched UDP decoder accepted datagram beyond IP length")
    return Result("016", "UDP payload may extend past IPv4 packet",
                  f"IP total length {ip_total} but UDP length {udp_len}; old check accepts capture length {len(frame)}")


if __name__ == "__main__":
    raise SystemExit(run_poc(poc))

