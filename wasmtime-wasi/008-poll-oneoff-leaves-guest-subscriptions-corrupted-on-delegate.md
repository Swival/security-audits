# poll_oneoff corrupts guest subscription memory on delegated error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p0.rs:443`
- `crates/wasi/src/p0.rs:857`
- `crates/wasi/src/p1.rs:2420`
- `crates/wasi/src/p1.rs:2445`
- `crates/wasi/witx/p0/typenames.witx:546`
- `crates/wasi/witx/p1/typenames.witx:550`
- `crates/wasi/witx/p0/wasi_unstable.witx:434`

## Summary
`poll_oneoff` in preview0 rewrites guest-provided `subs` entries in place into preview1 `Subscription` layout before delegating to `Snapshot1::poll_oneoff`. On delegated `Err`, the function returns early via `?` before restoring the saved preview0 entries. This leaves guest memory corrupted with the wrong ABI layout, despite `subs` being a const input buffer.

## Provenance
- Verified from the supplied reproducer and source review
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Guest calls `poll_oneoff`
- Delegated `Snapshot1::poll_oneoff` returns `Err`
- At least one subscription entry has already been rewritten in place before the error is returned

## Proof
- `poll_oneoff` reads guest-controlled subscriptions and overwrites them in place with preview1 `Subscription` values at `crates/wasi/src/p0.rs:443`.
- The original preview0 entries are saved in `old_subs`, but restoration occurs only after `Snapshot1::poll_oneoff(...).await?` completes successfully.
- Because `?` propagates delegated failure immediately, the restore loop is skipped on error.
- The layout mismatch is concrete: preview0 `subscription` includes an extra `identifier` field at `crates/wasi/witx/p0/typenames.witx:546`, while preview1 removed it at `crates/wasi/witx/p1/typenames.witx:550`.
- The conversion helper at `crates/wasi/src/p0.rs:857` copies only preview1 fields, so a rewritten slot is no longer valid preview0 memory.
- The delegated error is guest-reachable: `Snapshot1::poll_oneoff` returns `Badf` for invalid or unsupported fd subscriptions at `crates/wasi/src/p1.rs:2420` and `crates/wasi/src/p1.rs:2445`.
- A guest can therefore submit a valid clock subscription followed by an invalid fd subscription, trigger delegated `Err(Badf)`, and observe the earlier slot left in preview1 layout.
- This also violates the declared ABI contract because preview0 defines `subs` as `const_pointer $subscription` at `crates/wasi/witx/p0/wasi_unstable.witx:434`.

## Why This Is A Real Bug
This is not a theoretical cleanup issue. The function mutates caller-owned input memory and fails to restore it on a reachable error path controlled by guest input. The corrupted buffer no longer matches the preview0 ABI, so the guest can observe invalid data in an argument that should remain immutable. That is a correctness and ABI-integrity violation.

## Fix Requirement
Ensure `old_subs` is restored before every return from `poll_oneoff`, including delegated-error paths from `Snapshot1::poll_oneoff`.

## Patch Rationale
The patch wraps the delegated call so restoration runs unconditionally before propagating the result. This preserves the existing conversion strategy while closing the early-return gap. It directly satisfies the requirement that guest `subs` memory is restored even when delegation fails.

## Residual Risk
None

## Patch
- Patched in `008-poll-oneoff-leaves-guest-subscriptions-corrupted-on-delegate.patch`
- The fix restores saved preview0 subscriptions on both success and error paths before returning from `poll_oneoff`