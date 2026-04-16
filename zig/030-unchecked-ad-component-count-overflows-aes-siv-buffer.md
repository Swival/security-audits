# Unchecked AES-SIV AD Component Count Causes Panic

## Classification

- Type: Denial of Service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/aes_siv.zig:286`
- Function: `decryptWithAdVector`

## Summary

`decryptWithAdVector` copies attacker-supplied associated-data components into a fixed `[128][]const u8` buffer and then unconditionally appends the decrypted plaintext. With too many AD components, the plaintext append indexes past the fixed buffer, causing a safe-build bounds-check panic before authentication failure is returned.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- A service maps a peer-controlled associated-data vector into `decryptWithAdVector`.

## Proof

`decryptWithAdVector` allocates:

```zig
var strings_buf: [128][]const u8 = undefined;
var strings_len: usize = 0;
```

It then copies every AD component:

```zig
for (ad) |a| {
    strings_buf[strings_len] = a;
    strings_len += 1;
}
```

Finally, it always appends plaintext:

```zig
strings_buf[strings_len] = m;
strings_len += 1;
```

With `ad.len == 128`, the loop fills `strings_buf[0]` through `strings_buf[127]`, leaving `strings_len == 128`. The plaintext append then writes `strings_buf[128]`, which is out of bounds.

The reproducer called:

```zig
Aes128Siv.decryptWithAdVector(&plaintext, ciphertext, tag, &ad_128_components, key);
```

with 128 empty AD components. In a safe Zig build it aborts with:

```text
panic: index out of bounds: index 128, len 128
lib/std/crypto/aes_siv.zig:288:24: in decryptWithAdVector
    strings_buf[strings_len] = m;
```

This occurs before S2V tag recomputation and before returning `error.AuthenticationFailed`.

## Why This Is A Real Bug

The failure is reachable from unauthenticated input under the stated precondition. Instead of rejecting malformed or excessive AD vectors with an authentication error, the function panics in safe builds. In services where a remote peer controls the AD component count, this can terminate the operation or process, producing a practical denial of service.

Additionally, `s2v` asserts `strings.len <= 127`, so `decryptWithAdVector` must ensure the total S2V string count, including plaintext, does not exceed 127.

## Fix Requirement

Reject excessive AD component counts before filling `strings_buf` or invoking `s2v`.

Because plaintext is always appended as one additional S2V string, `decryptWithAdVector` must reject `ad.len >= 127`, allowing at most 126 AD components.

## Patch Rationale

The patch adds an early check:

```zig
if (ad.len >= 127) return error.AuthenticationFailed;
```

This prevents both:

- out-of-bounds writes to the fixed `[128][]const u8` buffer, and
- violation of the `s2v` limit requiring `strings.len <= 127`.

Returning `error.AuthenticationFailed` preserves the function’s authenticated-decryption error model and avoids exposing a panic path to unauthenticated callers.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/aes_siv.zig b/lib/std/crypto/aes_siv.zig
index 4cbbca2eeb..f50e773ed1 100644
--- a/lib/std/crypto/aes_siv.zig
+++ b/lib/std/crypto/aes_siv.zig
@@ -263,6 +263,7 @@ fn AesSiv(comptime Aes: anytype) type {
         /// an arbitrary vector of associated data strings as specified in RFC 5297.
         pub fn decryptWithAdVector(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const []const u8, key: [key_length]u8) AuthenticationError!void {
             assert(c.len == m.len);
+            if (ad.len >= 127) return error.AuthenticationFailed;
 
             // Split key into K1 (for S2V) and K2 (for CTR)
             const k1 = key[0 .. Aes.key_bits / 8];
```