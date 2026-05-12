# Oversized Trailer Reference Writes Past Block Arrays

## Classification

- Type: out-of-bounds write
- Severity: medium
- Confidence: certain

Threat model note: `CheckpointTrailer.open()` consumes `reference.trailer_size` taken from the local superblock. The realistic trigger is *disk corruption that happens to produce a valid superblock quorum*, or an attacker with local-filesystem access who can craft a data file. Under `ReleaseSafe` (TigerBeetle's shipping mode) Zig's bounds checks turn the OOB write into a trap; under `ReleaseFast` (no safety) the OOB write would actually occur. The patch is an assertion, so it provides the same coverage profile as the underlying bounds check rather than adding unconditional hardening — useful as defense in depth and as documentation of the invariant, but it does not change behavior in safety-enabled builds.

## Affected Locations

- `src/vsr/checkpoint_trailer.zig:272`

## Summary

`CheckpointTrailer.open()` trusted `reference.trailer_size` from the superblock before checking that the initialized trailer buffers were large enough for that size. If the reference required more trailer blocks than were allocated during `init()`, opening a non-empty trailer caused `open_read_next()` to decrement `block_index` from the oversized untrusted block count and write past `block_addresses` and `block_checksums`.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Status: reproduced and patched

## Preconditions

- The opener initializes a trailer with a smaller `buffer_size` than the supplied `reference.trailer_size`.
- A malicious storage backend or attacker-controlled data file supplies a checksummed superblock quorum.
- The superblock trailer reference has a nonzero `last_block_address` and a `trailer_size` requiring more blocks than the locally allocated arrays.

## Proof

`CheckpointTrailer.init()` allocates `blocks`, `block_bodies`, `block_addresses`, and `block_checksums` for:

```zig
block_count_for_trailer_size(buffer_size)
```

During open, `CheckpointTrailer.open()` copied the storage-supplied value directly:

```zig
trailer.size = reference.trailer_size;
```

It then set:

```zig
trailer.block_index = trailer.block_count();
```

where `trailer.block_count()` is computed from the untrusted `reference.trailer_size`.

For nonzero trailers, `open()` called `open_read_next()`, which decremented `block_index` and immediately wrote:

```zig
trailer.block_addresses[trailer.block_index] = address;
trailer.block_checksums[trailer.block_index] = checksum;
```

If `reference.trailer_size` required more blocks than were allocated from `buffer_size`, the first write indexed beyond the end of those arrays, before any block read or trailer checksum validation occurred.

The reproduced path includes `open()` passing `superblock.working.free_set_reference()` into `CheckpointTrailer.open()` from `src/vsr/grid.zig:300`. Existing superblock consistency checks did not bound free-set trailer sizes: `VSRState.assert_internally_consistent()` only required a nonzero free-set size when the last block address was nonzero in `src/vsr/superblock.zig:223`.

## Why This Is A Real Bug

The trailer size is derived from storage-controlled superblock data, while the backing arrays are sized from a local initialization buffer. The old code used the untrusted size to compute array indexes without checking that the arrays were large enough.

With Zig safety checks enabled, this is an attacker-triggered startup denial of service. With runtime safety disabled, it is an out-of-bounds write into checkpoint opener memory.

## Fix Requirement

Reject or trap on any `reference.trailer_size` whose computed trailer block count exceeds the number of blocks allocated by `CheckpointTrailer.init()`.

## Patch Rationale

The patch adds a bound check in `CheckpointTrailer.open()` before `trailer.size` is assigned and before `block_index` is derived from the untrusted trailer size:

```zig
assert(block_count_for_trailer_size(reference.trailer_size) <= trailer.blocks.len);
```

This ensures every subsequent index derived from `reference.trailer_size` is within the arrays allocated for the trailer opener.

## Residual Risk

The patch uses `assert`, which compiles away in `ReleaseFast`. In builds with safety disabled, the OOB write would still occur. For unconditional protection across all build modes, an explicit `vsr.fatal(.superblock_invalid, ...)` (or equivalent error return) would be a stronger fix. As written, the patch matches the codebase's prevailing style of using assertions to document and enforce invariants in trusted-storage code paths.

## Patch

```diff
diff --git a/src/vsr/checkpoint_trailer.zig b/src/vsr/checkpoint_trailer.zig
index 08f1a074b..5dc78b262 100644
--- a/src/vsr/checkpoint_trailer.zig
+++ b/src/vsr/checkpoint_trailer.zig
@@ -231,6 +231,7 @@ pub fn CheckpointTrailerType(comptime Storage: type) type {
             defer assert(trailer.callback == .open);
 
             assert(reference.trailer_size % trailer.trailer_type.item_size() == 0);
+            assert(block_count_for_trailer_size(reference.trailer_size) <= trailer.blocks.len);
             assert(trailer.size == 0);
             assert(trailer.size_transferred == 0);
             assert(trailer.block_index == 0);
```
