# Caret spacing underflows on inconsistent source spans

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/zig/ErrorBundle.zig:225`

## Summary
`ErrorBundle.renderToWriter` assumes `SourceLocation.column >= (span_main - span_start)` when rendering the caret line. `SourceLocation` entries are accepted and copied without validation, so inconsistent span metadata can reach rendering. When `column` is smaller than the computed pre-caret width, unsigned subtraction underflows while computing the spacing passed to `splatByteAll`, causing a panic in safe builds and invalid behavior in general.

## Provenance
- Verified from the supplied reproducer and code path in `lib/std/zig/ErrorBundle.zig`
- Reference: https://swival.dev

## Preconditions
- A stored `ErrorBundle.SourceLocation` has nonzero `source_line`
- `span_main >= span_start`
- `column < (span_main - span_start)`

## Proof
The reproducer constructs a `SourceLocation` with:
- `column = 1`
- `span_start = 0`
- `span_main = 3`
- `span_end = 4`
- nonzero `source_line`

`addSourceLocation` stores this data without enforcing consistency. During `renderToWriter`, the code computes `before_caret = span_main - span_start`, yielding `3`, then evaluates spacing as `column - before_caret`, yielding `1 - 3` on an unsigned value. Running the reproducer reaches `renderToWriter` and aborts with `panic: integer overflow` in `lib/std/zig/ErrorBundle.zig`, confirming the underflow is reachable with malformed `SourceLocation` input.

## Why This Is A Real Bug
This is not a hypothetical invariant mismatch. The rendering path is directly reachable once an inconsistent `SourceLocation` is stored, and the reproducer demonstrates a concrete crash. The broader compiler pipeline may usually normalize spans, but `ErrorBundle` itself does not defend its rendering logic against malformed or externally constructed bundle data. That makes the renderer crashable on invalid-but-storable state, which is a real robustness bug in this API surface.

## Fix Requirement
Clamp or guard the spacing calculation before calling `splatByteAll`, so rendering never performs unsigned subtraction with `column < before_caret`. Saturating subtraction satisfies this requirement.

## Patch Rationale
The patch changes the spacing calculation in `lib/std/zig/ErrorBundle.zig` to avoid unsigned underflow when `column` is smaller than the span prefix width. This preserves existing behavior for valid inputs and degrades safely for inconsistent inputs by rendering with zero extra spacing instead of panicking.

## Residual Risk
None

## Patch
Patched in `076-caret-spacing-underflows-on-inconsistent-source-spans.patch` by replacing the unchecked subtraction used for caret padding with a guarded/saturating calculation in `lib/std/zig/ErrorBundle.zig`.