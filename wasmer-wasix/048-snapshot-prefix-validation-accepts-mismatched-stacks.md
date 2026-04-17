# Snapshot prefix validation accepts mismatched stacks

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/os/task/thread.rs:381`

## Summary
`add_snapshot` validated an existing snapshot path segment with `.zip(...).any(|(a, b)| a == b)`, which treated a segment as matching when any paired byte matched. This allowed incompatible stored stack prefixes to be preserved as descendants of a new snapshot path. As a result, stale snapshots remained reachable through `get_snapshot`, and subsequent restores could resume obsolete `rewind_stack` and `store_data`.

## Provenance
- Verified from the provided finding and reproducer against the project source
- External scanner reference: https://swival.dev

## Preconditions
- An existing snapshot path shares at least one matching byte with the caller-supplied `memory_stack` segment and `memory_stack_corrected` segment

## Proof
The vulnerable logic in `add_snapshot` accepted an existing segment when any byte matched after zipping the old and new segments. A minimal model of the committed behavior reproduces the issue:

```text
existing path: AB -> CD
new stack:     XBXD
```

Each old segment shares one byte with the new segment, so both segments are incorrectly accepted under the `.any(...)` check. The code then preserves the old descendant structure and stores the new snapshot beneath the stale `ABCD` lineage instead of the caller’s actual `XBXD` lineage. After that:
- the stale descendant snapshot is still returned by `get_snapshot`
- the new snapshot is attached under the wrong preserved path
- `stack_restore` can restore obsolete state because it uses the saved `rewind_stack` and `store_data` from the retrieved snapshot at `lib/wasix/src/syscalls/wasix/stack_restore.rs:53`

## Why This Is A Real Bug
Prefix validation must establish that the stored stack segment is a true prefix of the incoming stack state. The previous predicate established only partial overlap, not prefix equality. That breaks the snapshot tree invariant and causes stale snapshots to survive invalidation. This is observable behavior, not a theoretical concern, because the reproducer demonstrates both stale retrieval and incorrect attachment of a new snapshot under the preserved stale path.

## Fix Requirement
Require full prefix equality for both `memory_stack` and `memory_stack_corrected` segments before preserving descendants.

## Patch Rationale
The patch replaces the permissive byte-overlap test with strict prefix comparison for both stored segments. Descendants are now preserved only when the entire stored segment exactly matches the corresponding prefix of the new stack inputs. This restores the intended snapshot ancestry check and prevents mismatched stacks from keeping unrelated descendants alive.

## Residual Risk
None

## Patch
- Patched in `048-snapshot-prefix-validation-accepts-mismatched-stacks.patch`
- The fix tightens validation in `lib/wasix/src/os/task/thread.rs` so preserved snapshot segments must fully equal the corresponding incoming stack prefixes before descendant retention occurs