# tar entry size drives unbounded allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`src/libarchive_sys/bindings.rs:1263`

## Summary

`NextEntry::read_entry_data` trusted the libarchive-reported archive entry size and allocated a buffer of that exact size before reading or validating entry payload data. An attacker-controlled tar header could declare a very large positive size and force process memory exhaustion when the victim parsed the tarball.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim parses attacker-supplied tarball bytes with `NextEntry::read_entry_data`.

## Proof

`ArchiveIterator::init` opens attacker-controlled `tarball_bytes` with `read_open_memory`, and `ArchiveIterator::next` obtains entries via `archive_read_next_header`.

For each selected entry, `NextEntry::read_entry_data` did:

```rust
let size = unsafe { (*self.entry).size() };
if size < 0 {
    return Ok(IteratorResult::init_err(...));
}

let mut buf = vec![0u8; usize::try_from(size).expect("int cast")];
```

Only negative sizes were rejected. A tar header declaring a large positive entry size therefore directly controlled the allocation length.

The reproduced trigger confirmed that a tiny tar buffer with regular-file header `package/package.json` and size `1073741824` is accepted by `archive_read_next_header` and reported with that size before payload validation. Code paths such as `bun publish <tarball>` read attacker-controlled `package/package.json` and `package/README*` entries through `read_entry_data`, causing allocation of 1 GiB before archive data is validated.

## Why This Is A Real Bug

The allocation occurs before `archive.read_data` checks how much data is actually present. The attacker does not need to supply a large payload; the tar metadata alone can force a large allocation. This can exhaust memory, abort, or panic the process while handling an untrusted archive.

## Fix Requirement

Reject archive entries whose declared size exceeds a bounded maximum before allocating the destination buffer, or replace eager full-entry reads with bounded streaming.

## Patch Rationale

The patch adds a fixed maximum entry data size of 16 MiB in `NextEntry::read_entry_data` and rejects any negative or over-limit size before allocation:

```rust
const MAX_ENTRY_DATA_SIZE: i64 = 16 * 1024 * 1024;

let size = unsafe { (*self.entry).size() };
if size < 0 || size > MAX_ENTRY_DATA_SIZE {
    return Ok(IteratorResult::init_err(
        archive.as_mut_ptr(),
        b"invalid archive entry size",
    ));
}
```

This preserves existing error behavior for invalid sizes while preventing attacker-controlled tar headers from driving unbounded memory allocation.

## Residual Risk

None

## Patch

`098-tar-entry-size-drives-unbounded-allocation.patch` modifies `src/libarchive_sys/bindings.rs` to cap `NextEntry::read_entry_data` allocations at 16 MiB before constructing the `Vec<u8>`.