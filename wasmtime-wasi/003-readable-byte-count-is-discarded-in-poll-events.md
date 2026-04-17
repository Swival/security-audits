# Readable byte count discarded in poll events

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p1.rs:1516`
- `crates/wasi/src/p1.rs:2544`

## Summary
`poll_oneoff` computes the remaining readable byte count for regular files as `size.saturating_sub(position)`, but the emitted `EventFdReadwrite` hard-codes `nbytes: 1`. This discards the computed value and causes guests to receive incorrect readiness byte counts for `FdRead` subscriptions on readable regular files.

## Provenance
- Verified from the provided reproducer and code inspection
- Reference: https://swival.dev

## Preconditions
- A readable regular file is subscribed through `poll_oneoff` using `FdRead`

## Proof
- In `crates/wasi/src/p1.rs:1516`, guest-controlled `SubscriptionU::FdRead.file_descriptor` reaches `poll_oneoff`.
- For `Descriptor::File`, the code derives `nbytes` from file metadata and cursor position via `size.saturating_sub(position)`.
- In `crates/wasi/src/p1.rs:2544`, the event is built with `EventFdReadwrite { flags, nbytes: 1 }` instead of the computed `nbytes`.
- Therefore, when remaining bytes are `0` or greater than `1`, the returned `event.fd_readwrite.nbytes` is wrong.

## Why This Is A Real Bug
The interface contract defines `event_fd_readwrite.nbytes` as the number of bytes available for reading or writing. Returning a constant `1` violates that contract for regular files unless exactly one byte remains. This can mislead guests that use poll readiness counts to size reads or make control-flow decisions. The reproducer confirms the reachable path and the incorrect value propagation.

## Fix Requirement
Set `EventFdReadwrite.nbytes` to the previously computed `nbytes` value rather than the constant `1`.

## Patch Rationale
The patch is minimal and directly aligns the emitted poll event with the already-computed readable-byte count. It preserves existing readiness and flag behavior while restoring the intended semantics for regular-file `FdRead` subscriptions.

## Residual Risk
None

## Patch
```diff
diff --git a/crates/wasi/src/p1.rs b/crates/wasi/src/p1.rs
--- a/crates/wasi/src/p1.rs
+++ b/crates/wasi/src/p1.rs
@@
-                    let rwflags = types::Eventrwflags::empty();
-                    let fd_readwrite = types::EventFdReadwrite {
-                        flags: rwflags,
-                        nbytes: 1,
-                    };
+                    let rwflags = types::Eventrwflags::empty();
+                    let fd_readwrite = types::EventFdReadwrite {
+                        flags: rwflags,
+                        nbytes,
+                    };
```