# Oversized CCM Ciphertext Aborts Verification

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

- `lib/std/crypto/aes_ccm.zig:233`
- Public affected variants using `nonce_len = 13`, including:
  - `Aes128Ccm0`
  - `Aes128Ccm8`
  - `Aes128Ccm16`
  - `Aes256Ccm0`
  - `Aes256Ccm8`
  - `Aes256Ccm16`

## Summary

`decrypt` accepted ciphertext lengths larger than the CCM maximum for the configured nonce length. For `nonce_len = 13`, CCM uses `L = 2`, so the encoded message length is limited to `65535` bytes.

When an attacker supplies a ciphertext of length `65536` or larger, `decrypt` proceeds into CTR processing and CBC-MAC computation. CBC-MAC formatting then narrows `msg_len` into a `u16` using `@intCast`, which traps under runtime integer-cast safety before authentication failure can be returned.

This allows a malicious sender to abort the process in Debug or ReleaseSafe builds.

## Provenance

Verified and patched from a Swival security finding.

Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- `nonce_len` is `13`.
- Runtime integer-cast safety is enabled.
- Attacker-controlled ciphertext reaches `decrypt`.
- Ciphertext length is greater than `65535` bytes.

## Proof

`decrypt` only asserted `m.len == c.len` and did not enforce the maximum message length that `encrypt` already checked.

Execution path:

1. `decrypt` accepts `c.len`.
2. `decrypt` decrypts with CTR into `m`.
3. `decrypt` calls `computeCbcMac(&mac_result, &key, m, ad, npub)`.
4. `computeCbcMac` calls `formatB0Block(&b0, m.len, ad.len, npub)`.
5. For `nonce_len = 13`, `L = 15 - nonce_len = 2`.
6. `formatB0Block` defines:

   ```zig
   const LengthInt = @Int(.unsigned, L * 8);
   ```

   Therefore `LengthInt` is `u16`.

7. It then executes:

   ```zig
   mem.writeInt(LengthInt, block[1 + nonce_length ..][0..L], @as(LengthInt, @intCast(msg_len)), .big);
   ```

8. For `msg_len >= 65536`, `@intCast(msg_len)` cannot fit in `u16` and traps before tag comparison.

Runtime reproduction confirmed:

```text
calling decrypt len=65536
thread ... panic: integer does not fit in destination type
.../lib/std/crypto/aes_ccm.zig:233:86: in formatB0Block
.../lib/std/crypto/aes_ccm.zig:186:26: in computeCbcMac
.../lib/std/crypto/aes_ccm.zig:137:30: in decrypt
```

Control case:

- Invalid-tag decrypt with length `65535` returned `error.AuthenticationFailed`.
- Invalid-tag decrypt with length `65536` panicked.

## Why This Is A Real Bug

Authentication failure for attacker-controlled invalid ciphertext should be reported as `error.AuthenticationFailed`, not as a process-aborting safety panic.

The length limit is a protocol requirement: CCM encodes the message length in `L` bytes. `encrypt` already enforced this bound, proving the implementation recognizes the invariant. `decrypt` missed the same validation, allowing unauthenticated input to reach a narrowing cast that can trap.

The attack requires only a `65536`-byte ciphertext for the common public `nonce_len = 13` CCM variants, making the denial of service practical.

## Fix Requirement

Before CTR or MAC processing in `decrypt`, reject ciphertexts whose length cannot be encoded in the CCM `L`-byte message length field.

The rejection must occur before any call path that casts `c.len` or `m.len` into the `L`-byte integer type.

## Patch Rationale

The patch mirrors the maximum message length calculation already used by `encrypt` and applies it to `decrypt`.

For oversized ciphertexts, `decrypt` now returns `error.AuthenticationFailed` before:

- CTR decryption,
- CBC-MAC computation,
- `formatB0Block`,
- the narrowing `@intCast`.

This preserves the authenticated-decryption API contract and prevents attacker-controlled length values from triggering safety traps.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/aes_ccm.zig b/lib/std/crypto/aes_ccm.zig
index 2f14e61d60..130afffba5 100644
--- a/lib/std/crypto/aes_ccm.zig
+++ b/lib/std/crypto/aes_ccm.zig
@@ -122,6 +122,10 @@ fn AesCcm(comptime BlockCipher: type, comptime tag_len: usize, comptime nonce_le
         ) AuthenticationError!void {
             assert(m.len == c.len);
 
+            // Validate ciphertext length fits in L bytes
+            const max_msg_len: u64 = if (L >= 8) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(L * 8))) - 1;
+            if (c.len > max_msg_len) return error.AuthenticationFailed;
+
             const cipher_ctx = BlockCipher.initEnc(key);
 
             // Decrypt the ciphertext using CTR mode (starting from counter = 1)
```