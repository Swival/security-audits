# File URL path segments are not percent-encoded

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/utils.rs:20`

## Summary
`url_from_file_path()` constructs `file://` URLs by concatenating raw path segments into a string. When an absolute path contains reserved URL characters such as `?` or `#` inside a segment, those characters are interpreted as URL syntax instead of file-name data. The resulting `Url` is malformed for this use and later round-trips to a different filesystem path, causing valid local package paths to fail to load.

## Provenance
- Verified from the supplied reproducer and code-path inspection in this repository
- External scanner reference: https://swival.dev

## Preconditions
- An absolute filesystem path is passed to `url_from_file_path()`
- At least one path segment contains URL-reserved characters that must be percent-encoded, such as `?` or `#`

## Proof
- `lib/wasix/src/runtime/resolver/utils.rs:20` iterates path components and appends each `component.to_str()?` directly into a `file://` buffer without percent-encoding.
- For a path such as `/tmp/query?x.txt`, the function produces `file:///tmp/query?x.txt`.
- Along the reproduced path:
  - `lib/wasix/src/runtime/resolver/filesystem_source.rs:20` stores the malformed URL
  - `lib/wasix/src/runtime/resolver/inputs.rs:56` stores the malformed URL
  - `lib/wasix/src/runtime/package_loader/builtin_loader.rs:250` dispatches on the `file` scheme
  - `lib/wasix/src/runtime/resolver/utils.rs:66` calls `url.to_file_path()`
  - `lib/wasix/src/runtime/package_loader/builtin_loader.rs:255` opens the converted path
- `Url::to_file_path()` interprets `?x.txt` as a query, so the path becomes `/tmp/query`, not `/tmp/query?x.txt`.
- Result: the loader attempts to open the wrong file path and package loading fails for an otherwise valid local absolute path.

## Why This Is A Real Bug
This is reachable on the normal absolute-path resolver flow and changes program behavior for valid filesystem paths. The bug does not depend on undefined behavior or invalid input at the OS level; it arises because the code serializes file paths into URLs without required escaping. The reproduced failure shows concrete path truncation and a downstream wrong-file access attempt.

## Fix Requirement
Encode each path segment before building the `file://` URL, or use a standard library/helper that safely converts filesystem paths to file URLs.

## Patch Rationale
The patch updates the file-URL construction path to preserve segment data by percent-encoding reserved characters before `Url` parsing. This keeps `file` URLs semantically aligned with the original filesystem path and makes the later `to_file_path()` conversion lossless for valid absolute paths.

## Residual Risk
None

## Patch
- `026-file-url-builder-fails-to-percent-encode-path-segments.patch` percent-encodes path segments during `file://` URL construction in `lib/wasix/src/runtime/resolver/utils.rs`, preventing `?` and `#` from being misinterpreted as query or fragment delimiters during later resolution.