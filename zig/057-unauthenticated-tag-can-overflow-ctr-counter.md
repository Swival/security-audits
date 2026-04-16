# Unauthenticated Tag Can Overflow CTR Counter

## Classification

- Type: Denial of service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/aes_gcm_siv.zig:180`
- Root cause in shared CTR helper:
  - `lib/std/crypto/modes.zig:58`

## Summary

AES-GCM-SIV decryption used unauthenticated tag bytes as the initial CTR counter before verifying the tag. In checked-safe Zig builds, an attacker could set the first four tag bytes to a little-endian value near `2^32`, provide enough ciphertext blocks, and trigger an integer overflow panic inside `modes.ctrSlice` before authentication failed.

This allows remote denial of service for applications that decrypt attacker-supplied AES-GCM-SIV records in checked-safe mode.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Finding: `unauthenticated tag can overflow CTR counter`
- Reproduction status: Reproduced

## Preconditions

- The application decrypts attacker-supplied AES-GCM-SIV records.
- The application runs in checked-safe mode.
- The attacker can provide a forged tag and sufficiently long ciphertext.

## Proof

During decrypt, the implementation copies the peer-supplied tag into the CTR counter:

```zig
var counter: [16]u8 = tag;
counter[15] |= 0x80;

const aes_ctx = Aes.initEnc(message_key);
modes.ctrSlice(@TypeOf(aes_ctx), aes_ctx, m, c, counter, .little, 0, 4);
```

The tag is verified only after CTR decryption.

A reproduced runtime case used:

- all-zero key
- all-zero nonce
- all-zero ciphertext
- 128-byte ciphertext length
- tag first four bytes: `ff ff ff ff`

In checked mode, this panicked before authentication rejection:

```text
panic: integer overflow
lib/std/crypto/modes.zig:58:21: cnt_val += parallel_count;
lib/std/crypto/aes_gcm_siv.zig:180:27: modes.ctrSlice(...)
```

The overflowing operation was the CTR counter increment:

```zig
cnt_val += parallel_count;
```

Because the initial counter value came from unauthenticated attacker-controlled tag bytes, authentication did not protect this code path.

## Why This Is A Real Bug

Invalid authentication tags must be rejected by returning `error.AuthenticationFailed`, not by panicking. Here, attacker-controlled unauthenticated input reaches a checked arithmetic operation before authentication. A forged tag with a high 32-bit little-endian counter value can therefore terminate the process in checked-safe builds, creating a practical denial-of-service condition.

## Fix Requirement

CTR counter progression must not panic on attacker-influenced initial counter values. The implementation must either:

- authenticate before CTR processing where possible, or
- ensure CTR counter arithmetic wraps or rejects overflowing initial counters safely.

## Patch Rationale

The patch changes the CTR counter increment from checked addition to wrapping addition:

```zig
cnt_val +%= parallel_count;
```

This matches the existing use of wrapping addition when materializing per-lane counters:

```zig
cnt_val +% j
```

With wrapping arithmetic, forged unauthenticated tag values can no longer trigger a checked integer overflow panic before tag verification. Invalid tags will proceed to the normal constant-time tag comparison and return authentication failure.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/modes.zig b/lib/std/crypto/modes.zig
index ca8ecb90a6..1051b83614 100644
--- a/lib/std/crypto/modes.zig
+++ b/lib/std/crypto/modes.zig
@@ -55,7 +55,7 @@ pub fn ctrSlice(
             inline while (j < parallel_count) : (j += 1) {
                 mem.writeInt(CounterInt, counters[j * block_length + counter_offset ..][0..counter_size], cnt_val +% j, endian);
             }
-            cnt_val += parallel_count;
+            cnt_val +%= parallel_count;
             block_cipher.xorWide(parallel_count, dst[i .. i + wide_block_length][0..wide_block_length], src[i .. i + wide_block_length][0..wide_block_length], counters);
         }
         mem.writeInt(CounterInt, counterBlock[counter_offset..][0..counter_size], cnt_val, endian);
```