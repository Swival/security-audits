# Shared type flag references undefined enum member

## Classification
- Type: logic error
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/typed.d:210`

## Summary
`type2flags!T` handled `shared` types by OR-ing `AllocFlag.forSharing`, but `AllocFlag` has no such enum member. Any instantiation path that reaches `allocatorFor!(shared T)` therefore fails at compile time, blocking shared-type allocator selection in public typed-allocation APIs.

## Provenance
- Reproduced from the verified finding against the checked-out source
- Scanner source: https://swival.dev
- Reproducer compiled with `ldc2` against the local tree

## Preconditions
- Instantiate `type2flags` with a `shared` type
- Reach that code through a public API such as `allocatorFor!(shared T)` or `make!(shared T)`

## Proof
Using:
```d
import std.experimental.allocator.typed;
import std.experimental.allocator.gc_allocator : GCAllocator;
alias A = TypedAllocator!GCAllocator;
void main() { A a; auto alloc = &a.allocatorFor!(shared int)(); }
```

Compilation fails with:
```text
std/experimental/allocator/typed.d(233): Error: no property `forSharing` for type `AllocFlag`
std/experimental/allocator/typed.d(219): Error: template instance ... type2flags!(shared(int)) error instantiating
```

This demonstrates that `allocatorFor!(shared int)` cannot instantiate because `type2flags!T` references an undefined enum member.

## Why This Is A Real Bug
The failure is deterministic and occurs at compile time on a public API entrypoint. `allocatorFor(T)` routes typed allocator selection through `type2flags!T`; for `shared` types that logic is currently uncompilable. As a result, valid shared-type use cases are rejected, and downstream helpers that rely on `allocatorFor!(shared T)` are also broken.

## Fix Requirement
Replace the nonexistent `AllocFlag.forSharing` reference with behavior consistent with the actual flag model. Because `AllocFlag` already encodes `shared` together with `immutable` via `immutableShared`, the plain `shared` case must not reference a separate missing bit.

## Patch Rationale
The patch removes the invalid enum reference by making the plain `shared` branch contribute no additional flag bits. This restores compilation for `shared` types while preserving the existing scheme where only `immutable(T)` and `shared immutable(T)` map to `AllocFlag.immutableShared`.

## Residual Risk
None

## Patch
- Patch file: `060-shared-type-flag-references-undefined-enum-member.patch`
- Change: update `std/experimental/allocator/typed.d` so the `shared` branch in `type2flags!T` no longer references `AllocFlag.forSharing`
- Effect: `allocatorFor!(shared T)` and dependent typed-allocation APIs instantiate successfully again for shared types