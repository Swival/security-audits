# Write lock held across async filesystem load

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/bin_factory/mod.rs:160`

## Summary
`BinFactory::get_executable` held `self.local.write()` across an awaited filesystem/package load. The awaited path performs real file I/O and WEBC parsing, so concurrent callers on the same `BinFactory` could be stalled behind one exclusive cache lock, including cache hits and `set_binary()` updates.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner reference: https://swival.dev

## Preconditions
- Concurrent `get_executable` calls on one `BinFactory`

## Proof
At `lib/wasix/src/bin_factory/mod.rs:160`, user-controlled executable names flow into `BinFactory::get_executable`, which acquired the exclusive `self.local.write()` guard and then awaited `load_executable_from_filesystem(...)`.
The awaited slow path is non-trivial:
- `lib/wasix/src/bin_factory/mod.rs:223` opens the target file
- `lib/wasix/src/bin_factory/mod.rs:242` may `read_to_end().await`
- `lib/wasix/src/bin_factory/mod.rs:247` may call `BinaryPackage::from_webc(...).await`

Because the write lock remained held for the full duration of that async work, all other readers and writers of `self.local` were blocked until the load completed. Reachability is established by executable launch paths including:
- `lib/wasix/src/syscalls/wasix/proc_spawn.rs:244`
- `lib/wasix/src/syscalls/wasix/proc_exec3.rs:176`
- `lib/wasix/src/syscalls/wasix/proc_spawn2.rs:169`

## Why This Is A Real Bug
This is an exclusive lock held across attacker-reachable I/O and parsing. The result is cache-wide contention on a shared `BinFactory`: one slow executable lookup can delay unrelated cache hits and writers, creating a practical denial-of-service condition under concurrent process creation. The impact is amplified because successful `Executable::Wasm` filesystem loads were not cached, causing repeated absolute-path executions to re-enter the same lock-held slow path.

## Fix Requirement
Do not hold `self.local`'s write lock across `await`. Perform the filesystem/package load without the lock, then reacquire the lock only to publish the result if it is still absent.

## Patch Rationale
The patch moves async loading outside the critical section and uses a second lock acquisition only for insertion/check-after-load. This preserves correctness while removing lock-held I/O from the hot path. It also caches successful filesystem-loaded WASM executables so repeated lookups no longer re-trigger the expensive slow path.

## Residual Risk
None

## Patch
- `011-write-lock-held-across-async-filesystem-load.patch` changes `lib/wasix/src/bin_factory/mod.rs` to:
- check the local cache without holding a write lock across await
- call `load_executable_from_filesystem(...)` before taking the write lock
- reacquire the lock and insert only if the entry is still missing
- cache successful `Executable::Wasm` filesystem loads to avoid repeated slow-path contention