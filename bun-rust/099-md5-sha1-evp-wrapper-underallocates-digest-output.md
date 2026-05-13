# MD5-SHA1 EVP wrapper underallocates digest output

## Classification

Low severity latent out-of-bounds write (API footgun; no in-tree callers).

Confidence: certain on the type-vs-impl mismatch; low on reachability.

## Affected Locations

- `src/sha_hmac/sha.rs:201`

## Summary

The exported `MD5_SHA1` EVP wrapper declared its digest size as `SHA1_DIGEST_LENGTH` (`20`) while using `EVP_md5_sha1`, which writes a 36-byte digest: `MD5(16) || SHA1(20)`.

Because the generated safe Rust API accepts `&mut [u8; DIGEST]`, callers of `MD5_SHA1::{hash, final}` were instructed to provide a 20-byte buffer. The wrapper then passed that pointer directly to BoringSSL EVP functions with no output-length limit, allowing BoringSSL to write 36 bytes through a 20-byte Rust buffer.

## Provenance

Reported and reproduced via Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Caller can select or invoke the exported `bun_sha_hmac::MD5_SHA1` EVP digest wrapper.
- Caller uses the wrapper's declared output type, which was `&mut [u8; 20]`.
- The one-shot `hash` path or streaming `final` path is invoked.

## Proof

The vulnerable wrapper was generated as:

```rust
new_evp!(MD5_SHA1, SHA1_DIGEST_LENGTH, EVP_md5_sha1);
```

`SHA1_DIGEST_LENGTH` is `20`, so the generated API exposed:

```rust
pub fn hash(bytes: &[u8], out: &mut [u8; 20], engine: *mut ffi::ENGINE)
pub fn r#final(&mut self, out: &mut [u8; 20])
```

The one-shot path passes the 20-byte buffer directly to `EVP_Digest`:

```rust
ffi::EVP_Digest(
    bytes.as_ptr().cast::<c_void>(),
    bytes.len(),
    out.as_mut_ptr(),
    ptr::null_mut(),
    md,
    engine,
)
```

The streaming path passes the same-sized buffer directly to `EVP_DigestFinal`:

```rust
ffi::EVP_DigestFinal(&mut self.ctx, out.as_mut_ptr(), ptr::null_mut())
```

Neither call provides an output-capacity parameter. `EVP_md5_sha1()` produces a 36-byte digest, and project tests also expect a 36-byte `md5-sha1` digest in `test/js/node/crypto/node-crypto.test.js:132`.

A C proof of concept against OpenSSL-compatible EVP behavior confirmed that calling `EVP_Digest(..., out[20], NULL, EVP_md5_sha1(), NULL)` overwrites the 16-byte canary immediately following the 20-byte output buffer.

## Why This Is A Real Bug

This is reachable through a safe exported Rust API. The type signature promised that a 20-byte output buffer was sufficient, but the underlying C implementation writes 36 bytes.

The mismatch causes a deterministic 16-byte out-of-bounds write past the caller-provided digest buffer on both one-shot hashing and streaming finalization. The issue is not mitigated by Rust's array type because the write occurs through an FFI raw pointer.

The safer generic runtime EVP wrapper in `src/runtime/crypto/EVP.rs` sizes buffers from `EVP_MD_CTX_size`, so the confirmed bug is specific to the exported `sha_hmac` `MD5_SHA1` wrapper.

Note on reachability: `rg "MD5_SHA1::|MD5_SHA1\."` shows no in-tree callers of `hash`/`final`, and the `Md5Sha1` variant in `Algorithm` is commented out. The `Md5Sha1` exposure to user JS code is currently disabled. The wrapper is still `pub use`'d from `sha_hmac::lib`, so it remains a latent footgun for any future caller; severity is reduced because no current path reaches it.

## Fix Requirement

Declare the `MD5_SHA1` digest size as 36 bytes, or remove the wrapper entirely.

Any retained wrapper must ensure the Rust output buffer type matches the number of bytes written by `EVP_md5_sha1`.

## Patch Rationale

The patch changes the generated `MD5_SHA1` wrapper from a 20-byte digest to a 36-byte digest:

```diff
-new_evp!(MD5_SHA1, SHA1_DIGEST_LENGTH, EVP_md5_sha1);
+new_evp!(MD5_SHA1, 36, EVP_md5_sha1);
```

This makes the generated safe API require `&mut [u8; 36]` for both `hash` and `final`, matching the output size of `EVP_md5_sha1`.

The obsolete port note was removed because preserving the Zig `Sha1.digest_length` value was the source of the underallocation.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sha_hmac/sha.rs b/src/sha_hmac/sha.rs
index 111b5d65c5..320fe433d3 100644
--- a/src/sha_hmac/sha.rs
+++ b/src/sha_hmac/sha.rs
@@ -191,9 +191,7 @@ pub mod evp {
     new_evp!(SHA384, SHA384_DIGEST_LENGTH, EVP_sha384);
     new_evp!(SHA256, SHA256_DIGEST_LENGTH, EVP_sha256);
     new_evp!(SHA512_256, SHA512_256_DIGEST_LENGTH, EVP_sha512_256);
-    // PORT NOTE: Zig passes `Sha1.digest_length` (20) here, which is faithfully
-    // preserved even though MD5+SHA1 is conventionally 36 bytes.
-    new_evp!(MD5_SHA1, SHA1_DIGEST_LENGTH, EVP_md5_sha1);
+    new_evp!(MD5_SHA1, 36, EVP_md5_sha1);
     new_evp!(Blake2, 256 / 8, EVP_blake2b256);
 
     // ──────────────────────────────────────────────────────────────────────
```