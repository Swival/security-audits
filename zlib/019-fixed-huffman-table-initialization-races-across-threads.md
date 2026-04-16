# Fixed Huffman table initialization races across threads

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/puff.c:491`

## Summary
`fixed()` performed unsynchronized lazy initialization of shared static fixed-Huffman decode tables. When two threads entered `puff()` on fixed-code blocks at the same time, one thread could consume partially constructed tables via `codes()`/`decode()`, causing spurious inflate failure or misdecode.

## Provenance
- Verified from the supplied reproducer and runtime evidence
- Source: local patch `019-fixed-huffman-table-initialization-races-across-threads.patch`
- Reference: https://swival.dev

## Preconditions
- Two threads call `puff()` concurrently
- Both inputs reach block type `1`, which routes through `fixed()`
- First-use table initialization has not yet completed in one thread before the other starts decoding

## Proof
The reproducer observed concurrent accesses to `fixed.virgin`, `fixed.lencnt`, `fixed.lensym`, `fixed.distcnt`, and `fixed.distsym` from initializer threads, with overlapping reads from `codes()` at `contrib/puff/puff.c:460` and `contrib/puff/puff.c:480`. In the same run, valid input failed with `ret=-11` (`distance too far back`), which is consistent with a corrupted fixed-Huffman decode path caused by partial table construction.

## Why This Is A Real Bug
The fixed-code tables are process-global state used as decoder invariants. Publishing them without synchronization allows another thread to observe `virgin` and the backing arrays in an intermediate state. That directly breaks correctness: the decoder may reject valid streams, or decode with incorrect symbols/distances. The reproducer demonstrated an actual failure, so this is not a theoretical data-race claim.

## Fix Requirement
Initialization of the fixed Huffman tables must happen exactly once with thread-safe publication semantics, or the tables must be built eagerly before any concurrent decoding can begin.

## Patch Rationale
The patch removes the thread-unsafe lazy-init window by making fixed-table construction occur safely before concurrent use. This ensures no caller can enter `codes()` with partially initialized `lencode` or `distcode`, preserving the decode-table invariant across threads.

## Residual Risk
None

## Patch
- `019-fixed-huffman-table-initialization-races-across-threads.patch` guards one-time fixed-table initialization so shared decode tables are fully constructed before publication to concurrent `puff()` callers
- The change is localized to `contrib/puff/puff.c` and addresses the root cause in `fixed()`, rather than the downstream symptom site at `contrib/puff/puff.c:491`