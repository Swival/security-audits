# Repaired archive can claim omitted oversized entry data

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/minizip/mztools.c:227`
- `contrib/minizip/mztools.c:240`
- `contrib/minizip/mztools.c:254`
- `contrib/minizip/mztools.c:290`

## Summary
`unzRepair()` can return success after encountering an entry whose advertised compressed size exceeds the signed `int` copy path. The function skips copying that entry's data, but still emits central-directory metadata for it, increments the entry count, writes EOCD, and reports success. The resulting repaired archive is structurally inconsistent and can silently omit file data.

## Provenance
- Reproduced from the committed code in `contrib/minizip/mztools.c`
- Scanner source: https://swival.dev
- The original finding described signed-offset overflow, but reproduction showed a narrower, real bug in the same repair flow: oversized entry data is omitted while metadata is still committed

## Preconditions
- A recovered ZIP contains at least one local entry whose declared compressed size exceeds the signed `int` range used by the copy loop
- `unzRepair()` processes that entry and continues to later entries

## Proof
A harness linked against the repository version of `contrib/minizip/mztools.c` was used with a crafted input:
- The first local header advertises `cpsize=uncpsize=0x80000000`
- The file then immediately contains a second small valid entry
- `unzRepair()` returns success with `ret=0`, `entries=2`, `bytes=1`
- The produced archive is only 179 bytes long
- Despite that, the first repaired local header still claims a 2 GiB member

This demonstrates that the function records the oversized entry in the repaired archive without preserving its data, violating the repair invariant and causing silent corruption/data loss.

## Why This Is A Real Bug
The bug is externally observable and corrupts output state:
- Success is reported even though the repaired archive does not faithfully contain the advertised entry payload
- Central-directory and EOCD metadata claim an entry that the output archive does not actually store
- Consumers of the repaired archive receive a structurally inconsistent ZIP, leading to extraction failure or silent data loss depending on parser behavior

This is not a theoretical overflow-only concern; it is a concrete integrity failure reachable from committed code with crafted ZIP metadata.

## Fix Requirement
`unzRepair()` must fail closed when an entry's declared sizes cannot be safely copied and represented by the repair logic. It must not emit central-directory records, increment `entries`, or return success for an entry whose payload was not actually repaired.

## Patch Rationale
The patch changes the repair path to validate oversized entry sizes before committing metadata for the entry. If the entry cannot be safely copied within ZIP32 and local implementation limits, the function aborts repair for that entry instead of continuing with inconsistent bookkeeping. This preserves the core invariant that every emitted central-directory record corresponds to data actually written to the repaired archive.

## Residual Risk
None

## Patch
Patched in `028-negative-local-header-offset-written-after-signed-overflow.patch`.