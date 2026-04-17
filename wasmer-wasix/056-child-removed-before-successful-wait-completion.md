# Child removed before successful wait completion

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/proc_join.rs:143`

## Summary
A specific-child join removed the child from `inner.children` before any successful wait completion was established. On the non-blocking path, if `try_join()` returned `None` because the target was still running, the syscall returned without restoring the child entry, so the parent lost visibility of a live child.

## Provenance
- Verified from the supplied reproducer and source review
- Scanner reference: https://swival.dev

## Preconditions
- Target PID is still running
- Caller uses the specific-child join path
- The join attempt takes the non-blocking path and does not complete immediately

## Proof
In `proc_join_internal`, the specific-child path selected the matching child and removed it from `inner.children` before checking join completion. The non-blocking branch then called `process.try_join()`; when that returned `None` for a still-running child, the function returned `Err(Errno::Again)`/`Nothing` semantics without re-inserting the child. This was reproduced: after one non-blocking specific join against a live child, subsequent parent child-list based operations no longer observed that child even though it was still running.

## Why This Is A Real Bug
The parent-child registry is authoritative for child enumeration and any-child joins. Removing a child before the wait has actually completed violates resource lifecycle ordering: the child remains live, but parent bookkeeping says otherwise. That creates observable incorrect behavior, including `ECHILD`-style outcomes for a process that still has a running child.

## Fix Requirement
Only remove the child from `inner.children` after a join has completed successfully. Pending, unfinished, or non-blocking wait attempts must leave the child registered.

## Patch Rationale
The patch defers child removal until successful completion of the join operation. This preserves parent bookkeeping on incomplete waits while still removing the child once exit status is actually collected, matching expected wait/join semantics.

## Residual Risk
None

## Patch
- Patch file: `056-child-removed-before-successful-wait-completion.patch`
- Change scope: `lib/wasix/src/syscalls/wasix/proc_join.rs`
- Effect: specific-child non-blocking joins no longer drop live children from the parent list before completion