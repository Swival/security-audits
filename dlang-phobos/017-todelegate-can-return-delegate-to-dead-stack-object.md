# toDelegate returns delegates with dangling stack context

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/functional.d:1509`

## Summary
`toDelegate` accepts non-delegate callables by `auto ref` and can build a delegate whose context pointer is the address of that callable. When the argument is a stack-local callable object, the returned delegate outlives the storage backing its context and later calls dereference dead stack memory.

## Provenance
- Verified from reproduced behavior and source inspection
- Scanner reference: https://swival.dev

## Preconditions
- `toDelegate` is called on a stack-local callable object
- The produced delegate is returned, stored, or otherwise invoked after the callable's scope ends

## Proof
At `std/functional.d:1509`, `toDelegate` forwards non-delegate callables into delegate construction paths that preserve the callable address as delegate context. For function-pointer-style wrapping, `buildDelegate` assigns `df.contextPtr = cast(void*) fp`, embedding the callable object's address into the returned delegate. If `fp` denotes a stack-local callable, that address becomes invalid once the defining scope returns.

The reproducer returns delegates created from a local callable object. Runtime output shows both delegates carrying the same reused stack address and producing corrupted results instead of the expected values, proving use-after-scope on the delegate context.

## Why This Is A Real Bug
This is not a theoretical lifetime concern. The reproduced program demonstrates:
- identical delegate context pointers reused across separate calls
- post-return invocation reading stale stack memory
- incorrect results instead of the expected callable state

That is concrete undefined behavior from a dangling delegate context, reachable through normal library use.

## Fix Requirement
Prevent `toDelegate` from manufacturing delegates from unstable callable storage. It must reject stack-bound/rvalue callable objects and only permit conversions that preserve a valid lifetime, such as existing delegates or storage with independently stable lifetime.

## Patch Rationale
The patch narrows `toDelegate` so it no longer produces delegates backed by transient callable addresses. This directly removes the unsafe lifetime conversion at the API boundary rather than attempting to document or mask undefined behavior after construction.

## Residual Risk
None

## Patch
- Patch file: `017-todelegate-can-return-delegate-to-dead-stack-object.patch`
- The patch enforces the required lifetime restriction in `std/functional.d` so `toDelegate` cannot return delegates whose context points at dead stack storage.