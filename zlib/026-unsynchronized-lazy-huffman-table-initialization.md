# Unsynchronized lazy Huffman table initialization

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/blast/blast.c:260`

## Summary
`blast()` reaches `decomp()`, which lazily initializes shared static Huffman tables through an unsynchronized `if (virgin)` block. Concurrent first use allows multiple threads to write `virgin`, `litcnt`/`litsym`, `lencnt`/`lensym`, and `distcnt`/`distsym` at the same time, or lets one thread decode against partially constructed tables. This breaks the requirement that the tables are fully built before any call to `decode()`.

## Provenance
- Verified from supplied reproduction details and patch context
- Reproducer executed under ThreadSanitizer and reported data races in `decomp()` table initialization
- Reference: https://swival.dev

## Preconditions
- Two threads call `blast()` before one-time Huffman table initialization completes

## Proof
- `decomp()` uses function-local static state for lazy initialization: `virgin`, `litcnt`/`litsym`, `lencnt`/`lensym`, and `distcnt`/`distsym` at `contrib/blast/blast.c:260`.
- The initialization path checks `if (virgin)` and then invokes `construct()` three times to populate the shared count and symbol arrays before clearing the guard.
- There is no lock, atomic, or once primitive around that sequence, so concurrent callers can both enter initialization or observe partially written table contents.
- The reproduced run used two threads on the valid sample stream documented in the file header (`00 04 82 24 25 8f 80 7f`).
- ThreadSanitizer reported races on `decomp.virgin`, `decomp.litcnt`, `decomp.lencnt`, `decomp.lensym`, `decomp.distcnt`, and `decomp.distsym`, with accesses originating from the `if (virgin)` block and `construct()`.
- The race produced behavioral corruption in the same run: one thread decoded the sample to `AIAIAIAIAIAIA`, while the other returned `-3` after outputting only `AI`, hitting the "distance too far back" path at `contrib/blast/blast.c:342`.

## Why This Is A Real Bug
This is not a benign initialization race. The shared arrays are actively consumed by `decode()` as Huffman decoding tables. Partial or conflicting writes change decode decisions, which the reproduction demonstrated by turning a valid stream into a nondeterministic failure. That is observable misbehavior in normal multithreaded use of `blast()`, not merely a sanitizer-only concern.

## Fix Requirement
Replace the shared unsynchronized lazy initialization with thread-safe one-time setup, or remove runtime mutation entirely by using precomputed immutable tables.

## Patch Rationale
The patch in `026-unsynchronized-lazy-huffman-table-initialization.patch` removes the unsafe first-use race by ensuring the Huffman tables are no longer concurrently mutable during decoding. This directly restores the invariant that all threads see fully initialized tables before `decode()` uses them.

## Residual Risk
None

## Patch
- `026-unsynchronized-lazy-huffman-table-initialization.patch` applies the fix for `contrib/blast/blast.c` by eliminating the unsynchronized lazy table initialization path and ensuring thread-safe availability of the Huffman decode tables before use.