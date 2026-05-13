# Misaligned typed writes can perform invalid stores

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/outbuffer.d:98`

## Summary
`OutBuffer` permits `offset` to advance by arbitrary byte counts through byte-oriented writes and buffer-shaping helpers, but `write(ushort)` performs a typed store via `*cast(ushort*)&data[offset] = w`. When `offset` is odd, that expression creates a misaligned `ushort*` and issues an invalid aligned store, violating the module's alignment invariant.

## Provenance
- Verified finding reproduced locally against the committed source
- External scanner reference: https://swival.dev

## Preconditions
- `offset` is not aligned for `ushort` writes

## Proof
The bad path is directly reachable from normal API use:

```d
auto b = new OutBuffer();
b.write(cast(ubyte) 0x11);    // offset == 1
b.write(cast(ushort) 0x2233); // misaligned typed store
```

I verified this sequence compiles and runs against the committed `std/outbuffer.d`. I also compiled the underlying store pattern with `ldc2` to LLVM IR; the generated IR emits a `store i16` with `align 2` for a pointer derived from `i8* + offset`. That proves the compiler is instructed to treat the destination as 2-byte aligned even when `offset` is odd.

On the tested arm64 system, the write completed and produced bytes `11 33 22`, so the issue does not require an immediate crash to be real. The operation still performs a misaligned typed store and relies on undefined behavior.

## Why This Is A Real Bug
This is not a theoretical cleanliness issue. The implementation forms a typed pointer with stronger alignment requirements than the buffer state guarantees. That creates two concrete failure modes:
- on architectures that fault on unaligned accesses, the store can trap at runtime;
- under LLVM, the overstated alignment permits undefined-behavior-based optimization, which can lead to incorrect code generation even on hardware that tolerates unaligned memory access.

Because `offset` is user-reachable through ordinary byte writes before a `ushort` write, the invariant violation is practical and externally triggerable.

## Fix Requirement
Replace the aligned typed `ushort` store with a bytewise write sequence, or otherwise ensure `offset` is aligned before any multi-byte typed store occurs.

## Patch Rationale
The patch removes the invalid aligned typed store from `write(ushort)` and writes the value in a way that does not require stronger alignment than the buffer actually guarantees. This preserves behavior while eliminating the undefined misaligned access path.

## Residual Risk
None

## Patch
- Patch file: `072-misaligned-typed-writes-can-perform-invalid-stores.patch`