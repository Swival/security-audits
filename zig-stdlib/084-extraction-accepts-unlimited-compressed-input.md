# Extraction ignores declared compressed-size boundary

## Classification
High severity validation gap. Confidence: certain.

## Affected Locations
- `lib/std/zip.zig:487`

## Summary
`Entry.extract` trusts `self.uncompressed_size` for output length but, for deflate members, does not bound the compressed input to `self.compressed_size`. As a result, decompression can read past the declared ZIP entry payload and consume trailing archive bytes or appended data until it encounters a valid deflate terminator.

## Provenance
Verified from source and reproduction evidence. Reference: https://swival.dev

## Preconditions
- Extracting a ZIP entry with deflate compression

## Proof
In `lib/std/zip.zig:487`, the deflate branch constructs `flate.Decompress` directly over `stream.interface` after seeking to the entry data offset. No reader limit is applied from `self.compressed_size`, and the in-source `TODO limit based on self.compressed_size` confirms the missing boundary check.

This was reproduced with a malformed ZIP containing one deflate entry whose local and central headers both declared `compressed_size = 1`, while the actual raw deflate stream was 31 bytes. A Zig harness invoking `std.zip.extract` successfully extracted `a.txt` and printed `Hello from forged zip entry!`, proving decompression consumed bytes beyond the declared member length.

## Why This Is A Real Bug
ZIP entry boundaries are defined by metadata, including `compressed_size`. Ignoring that boundary lets a malformed archive cause extraction to process bytes outside the entry it claims to extract. This is not benign parser leniency: it breaks member isolation, permits consumption of later archive structures or appended data, and defeats validation that callers reasonably expect from ZIP metadata.

## Fix Requirement
Wrap the compressed entry source in a reader limited to `self.compressed_size` before passing it to the deflate decompressor, so extraction fails if the deflate stream does not terminate within the declared compressed member.

## Patch Rationale
The patch in `084-extraction-accepts-unlimited-compressed-input.patch` constrains the deflate input to the ZIP member’s declared compressed length before decompression. This aligns extraction behavior with ZIP entry metadata, preserves expected behavior for valid archives, and converts malformed overlong members into bounded failures instead of out-of-entry reads.

## Residual Risk
None

## Patch
`084-extraction-accepts-unlimited-compressed-input.patch`