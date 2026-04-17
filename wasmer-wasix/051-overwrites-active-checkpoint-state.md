# Overwrites active checkpoint state

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/journal/do_checkpoint_from_outside.rs:16`
- `lib/wasix/src/journal/effector/memory_and_snapshot.rs:188`
- `lib/wasix/src/syscalls/journal/actions/snapshot.rs:47`

## Summary
`do_checkpoint_from_outside` writes a caller-supplied checkpoint into `guard.checkpoint` without preserving the prior active state. The intended gate for `guard.checkpoint != WasiProcessCheckpoint::Execute` is commented out, so a second external checkpoint can overwrite an in-progress one before completion.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Scanner source: https://swival.dev

## Preconditions
- `guard.checkpoint` is already not `WasiProcessCheckpoint::Execute` when `do_checkpoint_from_outside` is called
- A second external checkpoint request arrives before the first checkpoint completes

## Proof
- In `lib/wasix/src/syscalls/journal/do_checkpoint_from_outside.rs:16`, the function locks process state and assigns the caller-provided `checkpoint` into `guard.checkpoint`
- The wait/retry logic that should block while `guard.checkpoint != WasiProcessCheckpoint::Execute` is commented out, so the overwrite is unconditional
- The reproduced case shows an `Explicit` checkpoint being replaced by `Sigint` during that window
- At completion, the checkpoint trigger is persisted into the journal as `JournalEntry::SnapshotV1 { when, trigger }` in `lib/wasix/src/journal/effector/memory_and_snapshot.rs:188`
- On replay, trigger cleanup uses the journaled trigger in `lib/wasix/src/syscalls/journal/actions/snapshot.rs:47`
- When `Explicit` is overwritten by `Sigint`, replay clears `Sigint` instead of the original one-shot trigger, leaving the original trigger armed after restore

## Why This Is A Real Bug
This is a concrete state-corruption path, not just a theoretical race. The overwrite changes the trigger metadata recorded for the snapshot, and replay then restores trigger state inconsistently with the pre-snapshot execution. That can cause a one-shot trigger that was already consumed to remain armed and fire again after restore.

## Fix Requirement
Restore gating so `do_checkpoint_from_outside` does not assign a new checkpoint while `guard.checkpoint` is not `WasiProcessCheckpoint::Execute`; it must wait or reject until the active checkpoint completes.

## Patch Rationale
The patch in `051-overwrites-active-checkpoint-state.patch` reinstates the missing gate before updating `guard.checkpoint`, preventing concurrent external checkpoint requests from replacing an active checkpoint and preserving the trigger metadata that snapshot completion and replay rely on.

## Residual Risk
None

## Patch
- `051-overwrites-active-checkpoint-state.patch` restores checkpoint-state gating in `lib/wasix/src/syscalls/journal/do_checkpoint_from_outside.rs` so an in-progress checkpoint cannot be overwritten by a second external request