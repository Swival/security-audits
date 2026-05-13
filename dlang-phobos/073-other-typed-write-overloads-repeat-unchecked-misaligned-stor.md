# Other typed write overloads use unchecked misaligned typed stores

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/outbuffer.d:111`

## Summary
`OutBuffer` typed write overloads such as `write(uint)` and `write(ushort)` reserve capacity and then write through `*cast(T*)&data[offset]` without enforcing natural alignment. If `offset` became misaligned through prior byte-granular writes, these overloads issue aligned typed stores to misaligned addresses.

## Provenance
- Verified from the provided reproducer and IR inspection
- Reproduced locally with a PoC using `write(ubyte)` followed by `write(uint)`
- Scanner reference: https://swival.dev

## Preconditions
- Caller invokes a typed `write(T)` overload when `OutBuffer.offset` is not naturally aligned for `T`
- `offset` was previously advanced by byte-wise writes such as `write(ubyte)` or `fill`

## Proof
The reproduced LLVM IR shows the bug is codegen-real, not hypothetical:
- In `outbuffer.ll:572`, `write(uint)` emits `store i32 ..., align 4`
- The destination pointer is derived from `data.ptr + offset`
- A prior one-byte write makes `offset == 1`, so this becomes an aligned-4 store to a misaligned address
- In `outbuffer.ll:622`, the `ushort` overload similarly emits `store i16 ..., align 2`

This matches the source path in `std/outbuffer.d:111`, where typed overloads reserve space and then store via a casted pointer into `data[offset]` without checking `offset % T.sizeof == 0`.

## Why This Is A Real Bug
This code is in `@trusted` territory and asserts an alignment property it does not actually maintain. On strict-alignment targets, the resulting stores can fault; on other targets, they still constitute undefined behavior under the generated aligned-store contract. The path is immediately reachable after any byte-sized write leaves `offset` misaligned.

## Fix Requirement
Replace typed pointer stores with an alignment-safe write mechanism. The preferred fix is byte-copy semantics, such as `memcpy` or equivalent slice-based copying, for all typed overloads that currently cast `&data[offset]` to `T*`.

## Patch Rationale
The patch in `073-other-typed-write-overloads-repeat-unchecked-misaligned-stor.patch` removes reliance on casted typed stores and uses byte-wise copying for the affected overloads. This preserves behavior while eliminating the unchecked alignment invariant and preventing the compiler from emitting aligned stores against potentially misaligned addresses.

## Residual Risk
None

## Patch
- File: `073-other-typed-write-overloads-repeat-unchecked-misaligned-stor.patch`
- Scope: updates typed write overloads in `std/outbuffer.d` to perform alignment-safe writes instead of unchecked `T*` stores