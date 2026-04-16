# AES-OCB Decrypt Authenticates Overwritten Associated Data

## Classification

- Type: `security_control_failure`
- Severity: Low
- Confidence: Certain
- Component: AES-OCB authentication tag verification

> Severity note: this is a correctness/hardening defect, not a remotely
> exploitable one. It only manifests when the caller deliberately passes
> overlapping `m` and `ad` slices; an attacker who controls only ciphertext
> bytes cannot force that aliasing. The std AEADs carry no `noalias`
> contract either way, so authenticating the AD exactly as supplied is the
> correct behaviour and the fix is free.

## Affected Locations

- `lib/std/crypto/aes_ocb.zig:244`
- Function: `AesOcb(...).decrypt`

## Summary

`AesOcb.decrypt` writes decrypted plaintext into `m` before computing the associated-data hash used for tag verification.

If the caller passes overlapping `m` and `ad` slices, the plaintext writes can modify the bytes later read by `hash(aes_enc_ctx, &lx, ad)`. The verifier then checks the tag against the post-write associated data instead of the caller-supplied pre-write associated data.

This allows decryption to return success for a tag that should reject for the original associated data.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Finding: `associated data can be overwritten before tag verification`

## Preconditions

- Caller invokes AES-OCB `decrypt`.
- `m` and `ad` slices overlap.
- The overlapping region of `ad` is modified by plaintext writes into `m` before tag verification.

## Proof

The reproduced case:

- Created a valid ciphertext/tag where associated data equals the plaintext.
- Prepared an output buffer containing different associated-data bytes.
- Called:

```zig
Aes128Ocb.decrypt(&out_and_ad, &c, tag_for_plaintext_ad, &out_and_ad, nonce, key)
```

- `decrypt` wrote plaintext into `out_and_ad`.
- Because `ad` aliases `m`, those writes changed the associated data before `hash()` was computed.
- The decrypt call returned success.
- The same ciphertext/tag with a non-overlapping copy of the original associated data rejected with `AuthenticationFailed`.

Observed output:

```text
decrypt accepted. pre_ad[0..4]=41 41 41 41, authenticated AD actually became plaintext[0..4]=61 75 74 68
control rejected with non-overlapping original AD
```

Relevant vulnerable flow:

```zig
m[(i + j) * 16 ..][0..16].* = p;
xorWith(&sum, p);
```

and later:

```zig
var computed_tag = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
```

For overlapping `m` and `ad`, `hash()` observes modified associated data.

## Why This Is A Real Bug

AES-OCB authenticates both ciphertext-derived plaintext and associated data. Associated data is security-critical input and must be verified exactly as supplied by the caller.

The current implementation permits caller-supplied associated data to be overwritten before it is authenticated. As a result, the authentication check can succeed for data different from the data originally passed as `ad`.

The reproducer demonstrates both sides deterministically:

- Overlapping `m`/`ad`: accepted.
- Non-overlapping original `ad`: rejected.

Therefore, the verifier fails to authenticate the intended associated data under the documented API behavior.

## Fix Requirement

The implementation must ensure tag verification uses the caller-supplied associated data, not data modified by plaintext output.

Acceptable fixes:

- Compute the associated-data hash before any writes to `m`.
- Or explicitly forbid and reject/assert overlapping `m` and `ad`.

## Patch Rationale

The patch computes `ad_hash` before any plaintext is written to `m`.

This preserves the existing API and in-place decryption behavior while ensuring associated data is captured before possible aliasing writes occur. Final tag computation then uses the saved `ad_hash` instead of re-reading `ad` after mutation.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/aes_ocb.zig b/lib/std/crypto/aes_ocb.zig
index 36e2aaa84c..92cc266bc4 100644
--- a/lib/std/crypto/aes_ocb.zig
+++ b/lib/std/crypto/aes_ocb.zig
@@ -186,6 +186,7 @@ fn AesOcb(comptime Aes: anytype) type {
             const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
             var lx = Lx.init(aes_enc_ctx);
             const lt = lx.precomp(x_max);
+            const ad_hash = hash(aes_enc_ctx, &lx, ad);
 
             var offset = getOffset(aes_enc_ctx, npub);
             var sum: [16]u8 = @splat(0);
@@ -233,7 +234,7 @@ fn AesOcb(comptime Aes: anytype) type {
             }
             var e = xorBlocks(xorBlocks(sum, offset), lx.dol);
             aes_enc_ctx.encrypt(&e, &e);
-            var computed_tag = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
+            var computed_tag = xorBlocks(e, ad_hash);
             const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
             if (!verify) {
                 crypto.secureZero(u8, &computed_tag);
```