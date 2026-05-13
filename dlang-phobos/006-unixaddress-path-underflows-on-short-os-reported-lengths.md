# UnixAddress.path underflows on short OS-reported lengths

## Classification
- Severity: High
- Type: Invariant violation
- Confidence: Certain

## Affected Locations
- `std/socket.d:1244`
- `std/socket.d:2052`

## Summary
`UnixAddress.path()` derives the slice length as `_nameLen - sockaddr_un.init.sun_path.offsetof` without enforcing `_nameLen >= sun_path.offsetof`. When `_nameLen` is shorter, the subtraction underflows and produces an enormous slice length over `sun.sun_path`, leading to out-of-bounds read behavior and process termination via allocation failure. This state is reachable through the public `UnixAddress(sockaddr_un)` constructor and also from OS-reported lengths passed through `setNameLen`.

## Provenance
- Verified from the supplied finding and local reproduction against `std/socket.d`
- Reference: https://swival.dev

## Preconditions
- AF_UNIX address with `_nameLen` smaller than `sockaddr_un.init.sun_path.offsetof`

## Proof
A minimal program using the public constructor reproduces the bug:
```d
import std.socket;
import core.sys.posix.sys.un : sockaddr_un;

void main() {
    sockaddr_un su;
    su.sun_family = AddressFamily.UNIX;
    auto a = new UnixAddress(su);
    auto p = a.path;
}
```

Observed behavior during reproduction:
- `nameLen=0`
- `core.exception.OutOfMemoryError: Memory allocation failed`

The fault occurs because `path()` slices `sun.sun_path[0 .. _nameLen - sockaddr_un.init.sun_path.offsetof]` with an underflowed upper bound when `_nameLen` is `0`.

## Why This Is A Real Bug
This is a concrete memory-safety failure in library code reachable through documented API usage. The reproducer does not depend on kernel behavior; constructing `UnixAddress` from a valid `sockaddr_un` with default length state is sufficient. The resulting underflow drives an oversized pointer slice and causes deterministic runtime failure. The same invalid state can also arise if OS-reported AF_UNIX lengths shorter than the path offset are accepted by `setNameLen`.

## Fix Requirement
Reject or neutralize `_nameLen` values below `sockaddr_un.init.sun_path.offsetof` before any path-length subtraction occurs, either in `setNameLen` or directly in `path()`.

## Patch Rationale
The patch enforces the missing lower-bound invariant for Unix socket name lengths so `path()` never subtracts from an undersized `_nameLen`. This preserves valid AF_UNIX behavior while preventing underflow for constructor-created and OS-populated addresses.

## Residual Risk
None

## Patch
Patched in `006-unixaddress-path-underflows-on-short-os-reported-lengths.patch`.