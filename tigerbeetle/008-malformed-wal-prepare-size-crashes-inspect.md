# Malformed WAL Prepare Size Crashes Inspect

## Classification

denial of service, low severity

## Affected Locations

`src/tigerbeetle/inspect.zig:592`

## Summary

`inspect_wal()` trusted the attacker-controlled WAL prepare header `size` field before slicing `prepare_buffer`. If `wal_prepare.size` exceeded `constants.message_size_max`, `tigerbeetle inspect ... wal <crafted-file>` hit a Zig slice bounds trap and aborted instead of reporting the malformed WAL entry.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `tigerbeetle inspect ... wal` on a crafted TigerBeetle data file.

## Proof

`inspect_wal()` allocates `prepare_buffer` with length `constants.message_size_max`, reads WAL prepare bytes from the data file, and parses `wal_prepare` from the attacker-controlled buffer.

Before the patch, `wal_prepare_body_valid` evaluated:

```zig
wal_prepare.valid_checksum() and
wal_prepare.valid_checksum_body(
    prepare_buffer[@sizeOf(vsr.Header)..wal_prepare.size],
);
```

The body slice used `wal_prepare.size` without first checking that it was within `prepare_buffer.len`.

A crafted WAL prepare header can set `size > constants.message_size_max`. Because the checksum is unkeyed, the file author can recompute `wal_prepare.valid_checksum()` after changing `size`, causing evaluation to continue to the slice expression. Zig then traps on:

```zig
prepare_buffer[@sizeOf(vsr.Header)..wal_prepare.size]
```

when `wal_prepare.size > prepare_buffer.len`.

## Why This Is A Real Bug

The inspect command is intended to decode corrupt files as much as possible. A malformed file-controlled header field instead caused process abort through a bounds trap before the tool could continue decoding or report corruption.

The issue is directly reachable from file content and does not require running a replica or modifying live state.

## Fix Requirement

Validate that `wal_prepare.size` is:

- at least `@sizeOf(vsr.Header)`
- no greater than `prepare_buffer.len`

before using it as a slice bound.

## Patch Rationale

The patch adds size bounds checks to the existing short-circuit chain before checksum-body validation:

```zig
const wal_prepare_body_valid =
    wal_prepare.size >= @sizeOf(vsr.Header) and
    wal_prepare.size <= prepare_buffer.len and
    wal_prepare.valid_checksum() and
    wal_prepare.valid_checksum_body(
        prepare_buffer[@sizeOf(vsr.Header)..wal_prepare.size],
    );
```

Zig short-circuit evaluation prevents the unsafe slice from being evaluated when `wal_prepare.size` is below the header size or beyond the allocated prepare buffer. Malformed entries are marked invalid rather than crashing inspect.

## Residual Risk

None

## Patch

```diff
diff --git a/src/tigerbeetle/inspect.zig b/src/tigerbeetle/inspect.zig
index 0a50a8673..8ba9ec116 100644
--- a/src/tigerbeetle/inspect.zig
+++ b/src/tigerbeetle/inspect.zig
@@ -589,6 +589,8 @@ const Inspector = struct {
             );
 
             const wal_prepare_body_valid =
+                wal_prepare.size >= @sizeOf(vsr.Header) and
+                wal_prepare.size <= prepare_buffer.len and
                 wal_prepare.valid_checksum() and
                 wal_prepare.valid_checksum_body(
                     prepare_buffer[@sizeOf(vsr.Header)..wal_prepare.size],
```