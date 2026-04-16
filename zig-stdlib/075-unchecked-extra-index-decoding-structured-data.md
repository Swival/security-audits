# Unchecked extra index decoding structured data

## Classification
- Type: `validation gap`
- Severity: `high`
- Confidence: `certain`

## Affected Locations
- `lib/std/zig/ErrorBundle.zig:104`
- `lib/std/zig/ErrorBundle.zig:109`
- `lib/std/zig/ErrorBundle.zig:111`
- `lib/std/zig/ErrorBundle.zig:184`
- `lib/std/zig/ErrorBundle.zig:199`

## Summary
Malformed non-empty `ErrorBundle` inputs can supply `extra` indexes and trailing lengths that are decoded without bounds validation. When rendering or copying the bundle, helpers such as `getErrorMessageList`, `getErrorMessage`, and `getSourceLocation` dereference `eb.extra` using attacker-controlled offsets, causing out-of-bounds reads and process aborts.

## Provenance
- Verified by local reproduction against the affected code path
- Swival Security Scanner: https://swival.dev

## Preconditions
- Consumer uses a non-empty malformed `ErrorBundle`

## Proof
A malformed serialized bundle reaches `renderToWriter` via `renderErrorMessageToWriter` and then decodes structured records through `extraData` in `lib/std/zig/ErrorBundle.zig:111`.

The reproduced case encoded:
- `ErrorMessageList{ len = 1, start = 3, compile_log_text = 0 }`
- one root message index of `999`
- `extra_len = 4`

Rendering the bundle follows:
- `renderToWriter` at `lib/std/zig/ErrorBundle.zig:184`
- `getMessages` at `lib/std/zig/ErrorBundle.zig:104`
- `renderErrorMessage` at `lib/std/zig/ErrorBundle.zig:199`
- `getErrorMessage` at `lib/std/zig/ErrorBundle.zig:109`
- `extraData` at `lib/std/zig/ErrorBundle.zig:111`

This aborts with:
```text
panic: index out of bounds: index 999, len 4
```

The same unchecked decoding pattern also applies to note arrays, source locations, reference traces, and string index lookups.

## Why This Is A Real Bug
The crash is triggered by a valid API consumer supplying malformed serialized `ErrorBundle` data; no undefined setup or unreachable state is required. The failing index is read directly from bundle-controlled metadata, so the issue is an input-validation bug in deserialization logic, not a misuse by the caller. The impact is denial of service in any consumer that renders or copies the bundle.

## Fix Requirement
Validate every base `extra` index before decoding structured records, and validate every derived trailing span before creating slices or reading trailer entries. Reject or safely handle invalid string indexes, message indexes, note spans, and reference-trace spans before dereferencing.

## Patch Rationale
The patch in `075-unchecked-extra-index-decoding-structured-data.patch` adds bounds validation around `extra`-backed decoding and trailer slice creation in `lib/std/zig/ErrorBundle.zig`, ensuring malformed indexes are detected before any `eb.extra[...]` access. This directly closes the reproduced crash path and the equivalent unchecked paths for related record types.

## Residual Risk
None

## Patch
- Patch file: `075-unchecked-extra-index-decoding-structured-data.patch`
- Target: `lib/std/zig/ErrorBundle.zig`
- Effect: adds strict bounds checks for structured `extra` decoding and dependent trailing slices before rendering or copying malformed `ErrorBundle` data