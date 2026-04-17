# Socketpair ignores requested family and type

## Classification
Medium severity validation gap. Confidence: certain.

## Affected Locations
- `lib/wasix/src/syscalls/wasix/sock_pair.rs:29`
- `lib/wasix/src/syscalls/wasix/sock_pair.rs:40`
- `lib/wasix/src/syscalls/wasix/sock_pair.rs:50`
- `lib/wasix/src/syscalls/wasix/sock_pair.rs:57`

## Summary
`sock_pair` accepted unsupported `af`, `ty`, and `pt` combinations and still returned descriptors by unconditionally creating `DuplexPipe` endpoints with socket rights. This produced apparent success for requests that were not actually implemented, and later socket-specific syscalls failed on the returned FDs with `Errno::Notsock` instead of rejecting the original call with `Errno::Notsup`.

## Provenance
Verified from the provided reproduction and source inspection in `lib/wasix/src/syscalls/wasix/sock_pair.rs`, with scanner provenance from Swival Security Scanner: https://swival.dev

## Preconditions
Ability to call `sock_pair` with arbitrary `af`, `ty`, and `pt`.

## Proof
`sock_pair` receives user-controlled `af`, `ty`, and `pt` at `lib/wasix/src/syscalls/wasix/sock_pair.rs:29`. Validation only rejected `SockProto::Tcp` with non-`Socktype::Stream` and `SockProto::Udp` with non-`Socktype::Dgram` at `lib/wasix/src/syscalls/wasix/sock_pair.rs:40`. All other protocols and address families flowed to `sock_pair_internal` at `lib/wasix/src/syscalls/wasix/sock_pair.rs:50`, which always created `DuplexPipe` descriptors and granted `Rights::all_socket()`.

The reproduction confirmed that unsupported inputs such as `af=Addressfamily::Unix`, `ty=Socktype::Seqpacket`, and `pt=SockProto::Icmp` succeeded, but subsequent socket operations including `sock_addr_local`, `sock_addr_peer`, `sock_status`, and `sock_get_opt_*` failed on those returned FDs with `Errno::Notsock`. The implementation comment at `lib/wasix/src/syscalls/wasix/sock_pair.rs:57` also explicitly noted that the socket properties were ignored.

## Why This Is A Real Bug
This is a contract violation, not a theoretical inconsistency. The syscall reported success for unsupported socketpair requests and returned descriptors labeled with socket rights even though they were pipe-backed objects lacking socket behavior. That creates false capability signaling, breaks caller assumptions, and defers the failure into later syscalls in a way that is externally observable and reproducible.

## Fix Requirement
Reject unsupported address families and any protocol other than supported `Tcp`/`Udp` combinations before reaching `sock_pair_internal`, and return `Errno::Notsup` for unsupported requests.

## Patch Rationale
The patch in `064-socketpair-ignores-requested-family-and-type.patch` tightens front-end validation in `sock_pair` so only implemented combinations are accepted. This prevents creation of pipe-backed descriptors for unsupported socketpair requests and restores fail-fast behavior at the syscall boundary, matching actual implementation support.

## Residual Risk
None

## Patch
`064-socketpair-ignores-requested-family-and-type.patch` rejects unsupported `af` values and non-`Tcp`/`Udp` protocol requests before `sock_pair_internal` is invoked, ensuring unsupported socketpair requests return `Errno::Notsup` instead of producing invalid socket-like FDs.