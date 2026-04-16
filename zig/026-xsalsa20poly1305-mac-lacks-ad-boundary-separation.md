# XSalsa20Poly1305 MAC lacks AD boundary separation

## Classification

- Type: security control failure
- Severity: critical
- Confidence: certain

## Affected Locations

- `lib/std/crypto/salsa20.zig:416`
- `XSalsa20Poly1305.encrypt`
- `XSalsa20Poly1305.decrypt`

## Summary

`XSalsa20Poly1305` authenticated `ad` and ciphertext by streaming both directly into Poly1305:

```zig
mac.update(ad);
mac.update(c);
```

No length, padding, or domain separator was MACed. Because `Poly1305.update()` is streaming, different `(ad, ciphertext)` splits with the same concatenation produced the same tag. A valid tag for `ad = "A", c = "BC"` also validated for `ad = "AB", c = "C"`.

## Provenance

- Verified by Swival security analysis.
- Scanner: https://swival.dev
- Reproduced with a local PoC against the committed stdlib implementation.

## Preconditions

- A verifier accepts attacker-supplied associated data, ciphertext, and a valid tag.
- The attacker can obtain or produce a valid `(ad, ciphertext, tag)` tuple and submit a different AD/ciphertext boundary with the same byte concatenation.

## Proof

The implementation derived the Poly1305 key, then authenticated:

```zig
mac.update(ad);
mac.update(c);
mac.final(tag);
```

`decrypt` repeated the same sequence and accepted when the computed tag matched.

Since no separator was included:

```text
update("A");  update("BC") == update("AB"); update("C")
```

Reproduction:

1. Encrypt a message with `ad = "A"`.
2. Keep the resulting ciphertext `c` and tag.
3. Call `XSalsa20Poly1305.decrypt` with:
   - forged AD: `"A" ++ c[0..1]`
   - forged ciphertext: `c[1..]`
   - same tag, key, and nonce
4. Decryption returned success.

This proves the authenticator did not bind the associated-data/ciphertext boundary.

## Why This Is A Real Bug

AEAD authentication must bind all authenticated inputs, including their boundaries. Associated data is commonly used for protocol metadata, routing fields, identities, sequence numbers, or headers. Accepting the same tag for a different AD/ciphertext split lets an attacker forge authenticated metadata while preserving the same raw MAC input stream.

The failure is deterministic and occurs in the public `XSalsa20Poly1305.decrypt` verifier.

## Fix Requirement

The MAC input must include unambiguous domain separation between associated data and ciphertext. At minimum, the implementation must MAC:

- associated data bytes,
- padding/domain separation after AD,
- ciphertext bytes,
- padding/domain separation after ciphertext,
- encoded AD length,
- encoded ciphertext length.

Encryption and decryption must use the identical MAC construction.

## Patch Rationale

The patch introduces `updateMac`, used by both `encrypt` and `decrypt`.

For non-empty AD, it authenticates:

1. `ad`
2. Poly1305 padding
3. `c`
4. Poly1305 padding
5. little-endian `u64` AD length
6. little-endian `u64` ciphertext length

This makes `(ad, c)` encodings injective for the affected AD-bearing API and prevents boundary-shifting forgeries.

For empty AD, the helper preserves existing behavior by authenticating only `c`, maintaining compatibility for existing `SecretBox` usage and existing test vectors where no associated data is present.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/salsa20.zig b/lib/std/crypto/salsa20.zig
index 36793eae2e..24743964f0 100644
--- a/lib/std/crypto/salsa20.zig
+++ b/lib/std/crypto/salsa20.zig
@@ -375,6 +375,24 @@ pub const XSalsa20Poly1305 = struct {
 
     const rounds = 20;
 
+    fn updateMac(mac: *Poly1305, ad: []const u8, c: []const u8) void {
+        if (ad.len == 0) {
+            // Preserves NaCl secretbox/crypto_secretbox compatibility, which has no
+            // associated data and MACs the ciphertext only.
+            mac.update(c);
+            return;
+        }
+        mac.update(ad);
+        mac.pad();
+        mac.update(c);
+        mac.pad();
+
+        var lengths: [16]u8 = undefined;
+        mem.writeInt(u64, lengths[0..8], @as(u64, ad.len), .little);
+        mem.writeInt(u64, lengths[8..16], @as(u64, c.len), .little);
+        mac.update(&lengths);
+    }
+
     /// c: ciphertext: output buffer should be of size m.len
     /// tag: authentication tag: output MAC
     /// m: message
@@ -391,8 +409,7 @@ pub const XSalsa20Poly1305 = struct {
         @memcpy(c[0..mlen0], block0[32..][0..mlen0]);
         Salsa20.xor(c[mlen0..], m[mlen0..], 1, extended.key, extended.nonce);
         var mac = Poly1305.init(block0[0..32]);
-        mac.update(ad);
-        mac.update(c);
+        updateMac(&mac, ad, c);
         mac.final(tag);
     }
 
@@ -413,8 +430,7 @@ pub const XSalsa20Poly1305 = struct {
         @memcpy(block0[32..][0..mlen0], c[0..mlen0]);
         Salsa20.xor(block0[0..], block0[0..], 0, extended.key, extended.nonce);
         var mac = Poly1305.init(block0[0..32]);
-        mac.update(ad);
-        mac.update(c);
+        updateMac(&mac, ad, c);
         var computed_tag: [tag_length]u8 = undefined;
         mac.final(&computed_tag);
 
```