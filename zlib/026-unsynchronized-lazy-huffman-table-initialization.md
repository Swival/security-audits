# Unsynchronized lazy Huffman table initialization

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/blast/blast.c:260`

## Summary
`blast()` reaches `decomp()`, which lazily initializes shared static Huffman decode tables via an unsynchronized `if (virgin)` block. Concurrent first use allows multiple threads to write `litcnt`/`litsym`, `lencnt`/`lensym`, and `distcnt`/`distsym` at the same time, or to decode against partially initialized tables. This causes nondeterministic output and spurious decode failures on valid input.

## Provenance
- Verified from the supplied reproducer and code path in `contrib/blast/blast.c`
- Reproduced under ThreadSanitizer with races reported on the shared initialization state and Huffman tables
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Two threads call `blast()` before table initialization completes

## Proof
- `decomp()` stores its Huffman tables in function-static storage: `virgin`, `litcnt`/`litsym`, `lencnt`/`lensym`, and `distcnt`/`distsym`.
- At `contrib/blast/blast.c:260`, initialization is gated only by `if (virgin)`, with no lock, once primitive, or atomic ordering.
- Inside that block, `construct()` mutates the shared table arrays in place, then `virgin` is cleared.
- A concurrent caller can therefore:
  - also enter the initialization block and race on the same arrays, or
  - observe partially written tables while `decode()` reads `count` and `symbol`.
- The reproducer launched two threads against the valid sample stream documented in the file header (`00 04 82 24 25 8f 80 7f`).
- ThreadSanitizer reported races on `decomp.virgin`, `decomp.litcnt`, `decomp.lencnt`, `decomp.lensym`, `decomp.distcnt`, and `decomp.distsym`, with writes originating from `construct()` and the lazy-init block in `blast.c`.
- The impact was observable in behavior: one thread decoded successfully to `AIAIAIAIAIAIA`, while the other returned `-3` after only `AI`, hitting the `"distance too far back"` validation at `contrib/blast/blast.c:342`.

## Why This Is A Real Bug
This is a real concurrency defect, not a theoretical hygiene issue. The shared decode tables are part of the functional correctness boundary for every call to `blast()`. The reproducer shows valid input intermittently failing during concurrent first use, proving that raced initialization can corrupt decoding and surface as user-visible nondeterministic errors.

## Fix Requirement
Replace unsynchronized lazy initialization with thread-safe one-time setup. Acceptable fixes include:
- precomputing the Huffman tables as immutable `static const` data, or
- guarding table construction with a one-time initialization primitive or equivalent lock

The fix must ensure no caller can read or write the shared tables until construction is fully complete.

## Patch Rationale
The patch in `026-unsynchronized-lazy-huffman-table-initialization.patch` removes the unsafe shared lazy-init pattern by making table setup deterministic and unavailable to concurrent mutation during decode. This directly eliminates the raced state identified by ThreadSanitizer and preserves the invariant that `decode()` only consumes fully initialized Huffman tables.

## Residual Risk
None

## Patch
- `026-unsynchronized-lazy-huffman-table-initialization.patch` fixes `contrib/blast/blast.c` by eliminating the unsynchronized first-use initialization path for the shared Huffman tables, so concurrent `blast()` calls no longer race on table construction or decode against partial state.