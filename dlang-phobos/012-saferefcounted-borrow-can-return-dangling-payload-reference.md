# SafeRefCounted `borrow` can return dangling payload reference

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/typecons.d:3369`
- `std/typecons.d:8469`
- `std/typecons.d:8501`

## Summary
`SafeRefCounted.borrow` forwards the callback result while the payload is only protected by a local scoped borrow handle. If the callback returns `ref` into the payload, that reference escapes after `borrow` returns and can outlive the last owner, producing a dangling reference and use-after-free.

## Provenance
- Verified from the reported source location and reproduced with a standalone program
- Scanner source: https://swival.dev

## Preconditions
- The callback passed to `borrow` returns a `ref` into the managed payload

## Proof
- In `std/typecons.d:3369`, `borrow` takes a scoped pointer to `refCount._refCounted._store._payload` and immediately returns `unaryFun!fun(*plPtr)`.
- The scoped local protecting the payload ends at function return, so any forwarded `ref` result is no longer tied to the borrow lifetime.
- The existing `problematicRefReturn` path in `std/typecons.d:8469` demonstrates that `borrow` accepts and forwards a `ref` return.
- The unittest at `std/typecons.d:8501` confirms the returned reference aliases the payload.
- Reproduction: obtain `int* p = &problematicRefReturn(rc)`, destroy the last `SafeRefCounted` owner, then allocate new `SafeRefCounted!int` objects until the freed heap slot is reused. Observed output showed the same address reused and reads through `p` changing from the original `123` to reused values such as `777`, `4`, and `4493`, proving use-after-free.

## Why This Is A Real Bug
The bug is source-reachable through normal `borrow` usage and the codebase already contains a demonstrating path that returns a payload alias by `ref`. Once the final owner is destroyed, the escaped reference points to freed storage. Although this path is not reachable from fully `@safe` code, it is still a real memory-safety flaw in supported `@system` usage.

## Fix Requirement
Reject or prevent `ref`-returning callbacks from `SafeRefCounted.borrow`; the API must not forward references whose lifetime can outlive the internal borrow guard.

## Patch Rationale
The patch in `012-saferefcounted-borrow-can-return-dangling-payload-reference.patch` enforces non-escaping `borrow` results by disallowing `ref` returns from the callback rather than attempting to preserve a borrow lifetime the API cannot express safely. This directly removes the dangling-reference path while preserving by-value borrowing behavior.

## Residual Risk
None

## Patch
- `012-saferefcounted-borrow-can-return-dangling-payload-reference.patch` blocks `ref`-returning callbacks from `SafeRefCounted.borrow`
- This aligns the implementation with the actual lifetime guarantees of the scoped payload borrow
- The patch eliminates the reproduced use-after-free primitive without changing valid by-value callback behavior