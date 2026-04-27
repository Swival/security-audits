# UNICODE_STRING Length Truncation

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/windows/api.rs:318`

## Summary

`UnicodeStrRef::new` computed UTF-16 byte lengths as `usize` and then cast them into the narrower `UNICODE_STRING.Length` and `UNICODE_STRING.MaximumLength` fields without checking range. For slices whose byte length exceeded `u16::MAX`, the cast truncated or wrapped the length, causing Windows APIs to receive a `UNICODE_STRING` that described an empty string or short prefix rather than the caller-provided string.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller builds `UnicodeStrRef` from a `&[u16]` whose byte length is greater than `u16::MAX`.

Reachable constructors include:

- `UnicodeStrRef::from_slice`
- `UnicodeStrRef::from_slice_with_nul`
- `unicode_str!` array arm

A practical std path exists through unstable `std::fs::Dir::open_file`:

`library/std/src/fs.rs:1596` -> `library/std/src/sys/fs/windows/dir.rs:60` -> `library/std/src/sys/pal/windows/mod.rs:91` -> `library/std/src/sys/fs/windows/dir.rs:96` -> `library/std/src/sys/fs/windows/dir.rs:102`

## Proof

`UnicodeStrRef::new` calculates:

- `len * 2` for `Length`
- `size_of_val(slice)` for `MaximumLength`

Before the patch, both values were cast directly into `c::UNICODE_STRING` fields:

```rust
s: c::UNICODE_STRING { Length: len as _, MaximumLength: max_len as _, Buffer: ptr },
```

Runtime reproduction of equivalent constructor logic confirmed truncation:

- `32768` UTF-16 code units produced `Length=0 MaximumLength=0`
- `32771` UTF-16 code units produced `Length=6 MaximumLength=6`

Thus, Windows receives an empty name or short prefix instead of the intended oversized name.

## Why This Is A Real Bug

`UNICODE_STRING.Length` and `UNICODE_STRING.MaximumLength` are narrower than `usize`. An unchecked cast after computing byte lengths silently changes the object name seen by Windows. This can cause operations to target the wrong relative object, operate on a prefix, or fail with misleading semantics instead of rejecting an unrepresentable name.

The bug is not merely theoretical because the public constructors accept arbitrary slices, and a std path can pass a dynamically converted path through `UnicodeStrRef::from_slice` after rejecting NULs but without capping length.

## Fix Requirement

Reject or assert before casting whenever `Length` or `MaximumLength` would exceed `u16::MAX`.

## Patch Rationale

The patch adds explicit bounds checks immediately after computing the byte lengths and before constructing `UNICODE_STRING`:

```rust
assert!(len <= u16::MAX as usize);
assert!(max_len <= u16::MAX as usize);
```

This prevents silent truncation and preserves the existing invariant stated in the file guidelines to avoid unchecked narrowing casts unless the value is proven in range.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/windows/api.rs b/library/std/src/sys/pal/windows/api.rs
index 25a6c2d7d8e..1ae5f0e55c3 100644
--- a/library/std/src/sys/pal/windows/api.rs
+++ b/library/std/src/sys/pal/windows/api.rs
@@ -316,6 +316,8 @@ const fn new(slice: &[u16], is_null_terminated: bool) -> Self {
             let len = slice.len() - (is_null_terminated as usize);
             (len * 2, size_of_val(slice), slice.as_ptr().cast_mut())
         };
+        assert!(len <= u16::MAX as usize);
+        assert!(max_len <= u16::MAX as usize);
         Self {
             s: c::UNICODE_STRING { Length: len as _, MaximumLength: max_len as _, Buffer: ptr },
             lifetime: PhantomData,
```