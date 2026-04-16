# Fixed Huffman Table Initialization Race

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/puff.c:491`

## Summary
`fixed()` lazily initialized shared static fixed-Huffman decode tables behind an unsynchronized `virgin` flag. When two threads entered `puff()` on fixed-code blocks at the same time, one thread could consume `lencode`/`distcode` and their backing arrays while the other thread was still constructing them, causing invalid decoding state, spurious failures, or wrong output.

## Provenance
- Verified finding reproduced against `contrib/puff/puff.c`
- Scanner source: https://swival.dev
- Runtime evidence showed concurrent writes to `fixed.virgin`, `fixed.lencnt`, `fixed.lensym`, `fixed.distcnt`, and `fixed.distsym`, alongside concurrent reads from `codes()` at `contrib/puff/puff.c:460` and `contrib/puff/puff.c:480`

## Preconditions
- Two threads call `puff()` on fixed-code blocks simultaneously
- The calls reach the first-time initialization path in `fixed()`

## Proof
- Input selecting block type 1 in `puff()` reaches `fixed()`
- `fixed()` used process-global static state: `virgin`, `lencnt`, `lensym`, `distcnt`, `distsym`, `lencode`, and `distcode`
- Initialization was performed lazily and without locking or one-time synchronization
- The reproduced run observed readers in `codes()` consuming these tables while initializer threads were still mutating them
- The same run produced a real failure on valid input: `ret=-11` (`distance too far back`), demonstrating misdecode from partially initialized fixed tables

## Why This Is A Real Bug
The decoder relies on a strict invariant: Huffman tables must be fully constructed before use. The unsynchronized `virgin` check allowed publication of partially built shared state to concurrent callers. The observed concurrent reads and writes, plus the reproduced spurious `distance too far back` error on valid compressed data, confirm exploitable behavior in threaded use rather than a theoretical data race.

## Fix Requirement
Use thread-safe one-time initialization for the fixed tables, or remove runtime lazy initialization by building the fixed tables eagerly before any concurrent decode can observe them.

## Patch Rationale
The patch removes the thread-unsafe first-call construction path by ensuring fixed Huffman tables are not published in a partially initialized state. This satisfies the decoder invariant for all callers and preserves existing decoding behavior for single-threaded and multi-threaded use.

## Residual Risk
None

## Patch
- Patch file: `019-fixed-huffman-table-initialization-races-across-threads.patch`
- Patched location: `contrib/puff/puff.c`
- Effect: fixed-table initialization is made safe for concurrent callers, preventing partially initialized Huffman tables from reaching `codes()`/`decode()`