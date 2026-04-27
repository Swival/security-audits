# LSDA-Controlled Indirect Pointer Dereference

## Classification

High severity vulnerability.

Confidence: certain.

## Affected Locations

`library/std/src/sys/personality/dwarf/eh.rs:265`

## Summary

`find_eh_action` accepts LSDA data and reads `start_encoding` before call-site table parsing. If malformed or attacker-controlled LSDA supplies an absolute pointer encoding with `DW_EH_PE_indirect`, `read_encoded_pointer` reads a raw pointer from LSDA and then dereferences that LSDA-supplied address. This can fault during unwinding or perform an attacker-directed pointer-sized memory read used as landing-pad base metadata.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Verified and reproduced from the supplied LSDA control-flow evidence.

## Preconditions

- The unwinder parses attacker-controlled or otherwise malformed LSDA.
- The LSDA contains an indirect absolute pointer encoding, such as `0x80`.
- The encoded LSDA pointer value is invalid or points to attacker-chosen readable memory.

## Proof

- `find_eh_action` receives LSDA as `lsda` and initializes `DwarfReader` over it.
- `start_encoding` is read directly from LSDA at `library/std/src/sys/personality/dwarf/eh.rs:77`.
- Because `start_encoding != DW_EH_PE_omit`, execution calls `read_encoded_pointer` before call-site parsing.
- For encoding `0x80`, the application bits select `DW_EH_PE_absptr` and the indirect bit is set.
- `read_encoded_pointer` reads a raw pointer value from LSDA at `library/std/src/sys/personality/dwarf/eh.rs:260`.
- Because `DW_EH_PE_indirect` is set, it dereferences that LSDA-supplied pointer at `library/std/src/sys/personality/dwarf/eh.rs:266`.

## Why This Is A Real Bug

The dereference target comes from LSDA bytes rather than trusted unwind metadata. Under the stated precondition, a malformed LSDA can force the unwinder to dereference an arbitrary absolute address before normal call-site validation. An unmapped address can crash unwinding, and a mapped address can be read and interpreted as landing-pad base metadata. This is unsafe behavior triggered by metadata parsing, not ordinary safe Rust data.

## Fix Requirement

Reject `DW_EH_PE_indirect` when the pointer encoding has no trusted base provenance, specifically for absolute LSDA pointers where `base_ptr.is_null()` and the value format is `DW_EH_PE_absptr`.

## Patch Rationale

The patch extends the existing absolute-pointer validation in `read_encoded_pointer`. Absolute encodings already require `DW_EH_PE_absptr` because there is no relative base that can provide provenance. The fix also rejects `DW_EH_PE_indirect` in that same branch, preventing an LSDA-supplied absolute address from being dereferenced.

Relative encodings remain unchanged, preserving supported behavior where the pointer is derived from a known base such as PC-relative, function-relative, text-relative, or data-relative metadata.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/personality/dwarf/eh.rs b/library/std/src/sys/personality/dwarf/eh.rs
index ef5112ad74f..c134b55b383 100644
--- a/library/std/src/sys/personality/dwarf/eh.rs
+++ b/library/std/src/sys/personality/dwarf/eh.rs
@@ -254,7 +254,7 @@ unsafe fn read_encoded_pointer(
     let mut ptr = if base_ptr.is_null() {
         // any value encoding other than absptr would be nonsensical here;
         // there would be no source of pointer provenance
-        if encoding & 0x0F != DW_EH_PE_absptr {
+        if encoding & 0x0F != DW_EH_PE_absptr || encoding & DW_EH_PE_indirect != 0 {
             return Err(());
         }
         unsafe { reader.read::<*const u8>() }
```