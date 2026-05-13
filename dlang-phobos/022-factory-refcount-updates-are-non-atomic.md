# Factory refcount updates are non-atomic

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `std/regex/internal/ir.d:467`
- `std/regex/internal/ir.d:535`

## Summary
`MatcherFactory.incRef` and `MatcherFactory.decRef` update a shared matcher reference count with plain `++` and `--`. When the same matcher instance is retained or released from multiple threads, these non-atomic operations can lose updates. A lost decrement can make `decRef` observe zero while references still exist, leading to premature `GC.removeRange` and `pureFree` of live matcher storage.

## Provenance
- Verified from the supplied reproducer and source analysis
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- The same matcher instance is referenced from multiple threads

## Proof
The reproduced path is source-grounded:

```d
// std/regex/internal/ir.d:467
++m.refCount;
--m.refCount;
```

`Matcher.refCount()` exposes shared mutable `size_t` storage, and these updates are unsynchronized. The reproducer concurrently executes aliasing saves against the same underlying matcher, causing `incRef` races where one increment can be lost. This leaves the counter lower than the true number of live wrappers.

Once the count is corrupted, later releases can drive `decRef` to zero too early. At that point `std/regex/internal/ir.d:535` frees the matcher:

```d
GC.removeRange(ptr);
pureFree(ptr);
```

A remaining live wrapper still holds `_engine`; subsequent destruction or matcher use can then dereference freed memory, producing use-after-free and potentially double-free behavior.

## Why This Is A Real Bug
The bug is reachable without relying on dubious global-sharing assumptions. Although some obvious static caches are thread-local in D unless declared `__gshared`, that does not matter here: `RegexMatch` aliasing alone is sufficient to share one matcher instance across threads. Because lifetime management is performed through the factory on that shared object, the racy refcount directly governs whether live memory is freed.

## Fix Requirement
Reference count updates and the zero-to-free transition must be synchronized. An acceptable fix is to make the refcount atomic and ensure only the thread that performs the final successful decrement executes matcher teardown, or to guard retain/release and free with a lock.

## Patch Rationale
The patch in `022-factory-refcount-updates-are-non-atomic.patch` makes matcher lifetime management thread-safe by removing the unsynchronized plain refcount mutations and replacing them with synchronized retain/release behavior. This closes the lost-update window and preserves the invariant that matcher storage is freed only after the last live reference is released.

## Residual Risk
None

## Patch
- Patched in `022-factory-refcount-updates-are-non-atomic.patch`
- Required change: synchronize `MatcherFactory.incRef` and `MatcherFactory.decRef`, including the final free path in `std/regex/internal/ir.d`