# WorkerLocalStorageRange slice drops consumed base offset

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/parallelism.d:2074`
- `std/parallelism.d:3299`

## Summary
`WorkerLocalStorageRange` tracks logical front-consumption with `beginOffset`. After `popFront`, indexed reads use `index + beginOffset`, but `opSlice` rebuilt a rebased `WorkerLocalStorage` and constructed a new range with `beginOffset == 0`. As a result, slicing a partially-consumed range shifted access back toward earlier worker slots and returned incorrect elements. The same codepath also exposed that `opIndexAssign` ignored `beginOffset`, causing writes after front-consumption to target the wrong slot as well.

## Provenance
- Verified from the reported finding and reproduced locally against the committed source
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- Obtain a `WorkerLocalStorageRange` via public `toRange`
- Consume at least one element from the front with `popFront`
- Then either:
  - slice the range with `opSlice`, or
  - assign through the range after front-consumption

## Proof
The issue reproduces with a minimal program:

```d
auto wl = pool.workerLocalStorage!int();
auto init = wl.toRange;
foreach (i; 0 .. init.length) init[i] = i + 1;

auto r = wl.toRange;
r.popFront();
auto s = r[1 .. r.length];

assert(r[0] == 2);  // passes
assert(s[0] == 3);  // fails: s[0] is 2
```

Observed behavior:
- after `popFront`, `r[0] = 2`
- after slicing, `s[0] = 2` though the expected logical element is `3`

Root cause from implementation behavior:
- `popFront` increments `beginOffset`
- `opIndex` reads `workerLocalStorage[index + beginOffset]`
- old `opSlice` advanced `data`, reduced `size`, and returned `typeof(this)(newWl)`
- that constructor reset `beginOffset` to `0`, discarding prior front-consumption
- `opIndexAssign` separately wrote through `workerLocalStorage[index]`, ignoring `beginOffset`

## Why This Is A Real Bug
This is a concrete semantic violation of range behavior: after consuming the front of a range, further slicing and indexing must remain relative to the new logical start. Instead, the implementation accessed earlier worker-local slots than the visible range represents. That produces incorrect reads and incorrect writes, directly affecting reductions, summaries, or any post-processing over worker-local data. The reproducer demonstrates a deterministic wrong result, not a hypothetical edge case.

## Fix Requirement
- Preserve `beginOffset` semantics across `WorkerLocalStorageRange.opSlice`
- Ensure writes through `WorkerLocalStorageRange` use the same logical offseting as reads
- Keep sliced ranges aligned with the original storage without rebasing away consumed-front state

## Patch Rationale
The patch in `010-workerlocalstoragerange-slice-drops-base-offset.patch` updates slicing to preserve the logical base offset instead of reconstructing a rebased `WorkerLocalStorage` that resets it. It also makes indexed assignment honor `beginOffset`, matching existing read behavior. This is the minimal fix that restores range correctness for both reads and writes after front-consumption.

## Residual Risk
None

## Patch
Implemented in `010-workerlocalstoragerange-slice-drops-base-offset.patch`.