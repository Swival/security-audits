# Replay Flag Cleared Too Early During Snapshot Restore

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/journal/restore_snapshot.rs:77`
- `lib/wasix/src/syscalls/wasix/thread_spawn.rs:137`

## Summary
`restore_snapshot` marked journal replay as finished before restored background threads were started. Those threads inherit the current environment state and can immediately execute journal-writing paths, allowing live events to be emitted while replay-driven restoration is still applying remaining thread state.

## Provenance
- Verified by reproduction against the affected code path
- Scanner: https://swival.dev

## Preconditions
- Snapshot contains spawned background threads
- Snapshot restoration still has pending post-replay work, including thread-state application
- A restored thread resumes quickly enough to hit a journaled operation before the restore loop completes

## Proof
`restore_snapshot` processes deferred replay work, then cleared `runner.ctx.data_mut().replaying_journal = false` before iterating `runner.spawn_threads` and calling `JournalEffector::apply_thread_state` for each restored thread in `lib/wasix/src/syscalls/journal/restore_snapshot.rs:77`.

Restored threads are spawned from an environment clone in `lib/wasix/src/syscalls/wasix/thread_spawn.rs:137`, so they observe the replay flag value present at spawn time. The code comment in `restore_snapshot` states restored background threads may immediately process requests once started. In the reproduced case, a resumed thread reached a journal-saving path before remaining thread states were restored, and the new event was written to the active journal while replay was still in progress.

## Why This Is A Real Bug
This is not a theoretical ordering issue. The implementation explicitly allows restored threads to run concurrently as soon as they are started, while replay completion was signaled earlier. That breaks the intended replay boundary: concurrent live execution can observe partially restored process state and emit fresh journal events interleaved with unfinished snapshot restoration. The result is inconsistent restoration ordering and possible journal corruption of the replay session.

## Fix Requirement
Keep `replaying_journal` set until all replay-driven restoration work completes, including restoration of every spawned thread state. Only clear the flag after the restore loop has finished.

## Patch Rationale
The patch moves the replay-flag transition to the true end of snapshot restoration, after all entries in `runner.spawn_threads` have been processed through `JournalEffector::apply_thread_state`. This preserves the existing restore sequence while ensuring any restored thread that begins running during this window still observes replay as active and cannot treat the journal as live prematurely.

## Residual Risk
None

## Patch
`038-replay-flag-cleared-before-restored-threads-start.patch` delays clearing `runner.ctx.data_mut().replaying_journal` until after restored thread states are fully applied in `lib/wasix/src/syscalls/journal/restore_snapshot.rs`, closing the race where resumed threads inherited `replaying_journal = false` before replay actually finished.