# Forged LINKEDIT Size Drives Unsafe Vector Length

## Classification

High severity out-of-bounds read / undefined behavior.

Confidence: certain.

## Affected Locations

`src/exe_format/macho.rs:744`

## Summary

A forged arm64 Mach-O `LC_SEGMENT_64` for `__LINKEDIT` can set an oversized `filesize`. During signing, `MachoSigner::sign()` used `Vec::set_len()` with `__LINKEDIT.fileoff + __LINKEDIT.filesize` without proving that length was within initialized storage. This allowed attacker-controlled Mach-O metadata to make the output slice extend past valid initialized bytes, causing out-of-bounds process memory reads into the written binary or a crash.

## Provenance

Verified and patched finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Arm64 Mach-O signing is enabled for the supplied object.
- The attacker controls a Mach-O object file.
- The object contains a forged `LC_SEGMENT_64 __LINKEDIT` whose `filesize` makes `fileoff + filesize` exceed the signer’s initialized buffer length.

## Proof

The reproduced data flow is:

- `MachoSigner::init()` copies the attacker-controlled `__LINKEDIT` `segment_command_64` into `self.linkedit_seg`.
- `MachoSigner::init()` only verifies `__LINKEDIT.fileoff` is after `__TEXT`; it does not bound `fileoff + filesize` against `obj.len()` or future vector capacity.
- `validate_segments()` checks ordering and overlap, not whether segment ranges fit inside the file.
- `MachoSigner::sign()` resizes `self.data` to `aligned_sig_off + total_sig_size`, where both values are derived from `LC_CODE_SIGNATURE.dataoff`, not from `__LINKEDIT.filesize`.
- `MachoSigner::sign()` then unsafely set `self.data.len()` to `self.linkedit_seg.fileoff + self.linkedit_seg.filesize`.
- `writer.write_all(&self.data)` wrote the extended slice, reading bytes beyond initialized vector storage.

## Why This Is A Real Bug

`Vec::set_len()` requires the new length to be less than or equal to capacity and all newly exposed bytes to be initialized. The vulnerable code trusted Mach-O metadata controlled by the input file to choose that length. Because the signer only initialized storage up to the computed signature end, an oversized `__LINKEDIT.filesize` could violate `Vec` invariants and expose out-of-bounds memory through the output writer.

## Fix Requirement

Reject `__LINKEDIT.fileoff + __LINKEDIT.filesize` if:

- The addition overflows.
- The result cannot fit in `usize`.
- The result exceeds the initialized signer buffer length, `aligned_sig_off + total_sig_size`.

Only call `Vec::set_len()` after those bounds are proven.

## Patch Rationale

The patch computes `final_len` with checked arithmetic and checked integer conversion:

- `checked_add()` rejects `fileoff + filesize` overflow.
- `usize::try_from()` rejects platform-size truncation.
- `final_len > aligned_sig_off + total_sig_size` rejects forged `__LINKEDIT` ranges beyond initialized storage.
- The remaining `set_len(final_len)` is safe because `final_len` is bounded by the length created by the earlier `resize()`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/exe_format/macho.rs b/src/exe_format/macho.rs
index 866eb0efc4..d160e05fcc 100644
--- a/src/exe_format/macho.rs
+++ b/src/exe_format/macho.rs
@@ -739,11 +739,18 @@ impl MachoSigner {
         }
 
         // Finally, ensure that the length of data we write matches the total data expected
-        // SAFETY: capacity >= aligned_sig_off + total_sig_size >= linkedit end (asserted by
-        // compute_signature_size sizing in write_section); bytes up to this length were initialized.
+        let final_len = self
+            .linkedit_seg
+            .fileoff
+            .checked_add(self.linkedit_seg.filesize)
+            .and_then(|len| usize::try_from(len).ok())
+            .ok_or(MachoError::OffsetOverflow)?;
+        if final_len > aligned_sig_off + total_sig_size {
+            return Err(MachoError::OffsetOutOfRange.into());
+        }
+        // SAFETY: final_len is bounded by the initialized length from resize above.
         unsafe {
-            self.data
-                .set_len((self.linkedit_seg.fileoff + self.linkedit_seg.filesize) as usize);
+            self.data.set_len(final_len);
         }
 
         // Write final binary
```