# Oversized ULEB128 Invalid Shift

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/personality/dwarf/mod.rs:42`

## Summary

`DwarfReader::read_uleb128` accepts arbitrarily long ULEB128 continuation sequences and shifts a `u64` payload by the accumulated `shift` value before validating that the shift is in range. With eleven continuation bytes, `shift` reaches 70, so the parser evaluates a `u64 << 70`. This panics with overflow checks enabled and misdecodes malformed oversized ULEB128 data without checks.

## Provenance

Reported and reproduced by Swival Security Scanner: https://swival.dev

## Preconditions

- A DWARF stream contains at least eleven ULEB128 continuation bytes.
- The malformed stream is passed to `DwarfReader::read_uleb128`.
- A reachable source path exists through LSDA parsing from unwinder-provided language-specific data.

## Proof

`read_uleb128` reads each byte from `DwarfReader.ptr`, ORs the low seven bits into `result`, then increments `shift` by 7. Continuation bytes keep the loop running.

The reproduced failing path is:

- `library/std/src/sys/personality/gcc.rs:323` obtains LSDA via `_Unwind_GetLanguageSpecificData`.
- `library/std/src/sys/personality/gcc.rs:338` passes that pointer into `eh::find_eh_action`.
- `library/std/src/sys/personality/dwarf/eh.rs:72` wraps the pointer in `DwarfReader`.
- `library/std/src/sys/personality/dwarf/eh.rs:92` reads `call_site_table_length` with `reader.read_uleb128()`.

A minimal LSDA shape reaches the bug: `DW_EH_PE_omit`, `DW_EH_PE_omit`, any call-site encoding byte, followed by eleven ULEB128 continuation bytes. On the eleventh continuation byte, `shift` is 70 and the parser performs the invalid `u64 << 70` operation at `library/std/src/sys/personality/dwarf/mod.rs:42`.

## Why This Is A Real Bug

ULEB128 values decoded into `u64` cannot validly require a left shift of 64 bits or more. The parser invariant is that oversized encodings must be rejected before performing an out-of-range shift. The existing implementation violates that invariant by shifting first and only checking the continuation condition afterward.

This is reachable from real exception-handling metadata parsing, not only from a direct unit-level call. Malformed LSDA can therefore trigger the invalid operation before call-site table bounds are established.

## Fix Requirement

Reject oversized ULEB128 encodings before executing the shift when `shift >= u64::BITS`.

## Patch Rationale

The patch adds:

```rust
assert!(shift < u64::BITS as usize);
```

immediately after reading the next byte and before:

```rust
result |= ((byte & 0x7F) as u64) << shift;
```

This preserves behavior for valid encodings and stops malformed oversized encodings before the invalid shift is evaluated. The check directly enforces the missing parser invariant at the vulnerable operation.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/personality/dwarf/mod.rs b/library/std/src/sys/personality/dwarf/mod.rs
index 2bc91951b49..236aacbb66a 100644
--- a/library/std/src/sys/personality/dwarf/mod.rs
+++ b/library/std/src/sys/personality/dwarf/mod.rs
@@ -39,6 +39,7 @@ pub unsafe fn read_uleb128(&mut self) -> u64 {
         let mut byte: u8;
         loop {
             byte = unsafe { self.read::<u8>() };
+            assert!(shift < u64::BITS as usize);
             result |= ((byte & 0x7F) as u64) << shift;
             shift += 7;
             if byte & 0x80 == 0 {
```