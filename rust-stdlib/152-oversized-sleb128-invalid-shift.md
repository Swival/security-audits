# oversized SLEB128 invalid shift

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/personality/dwarf/mod.rs:57`

## Summary

`DwarfReader::read_sleb128` shifted a `u64` by an unchecked, attacker-controlled SLEB128 shift count. An oversized SLEB128 with enough continuation bytes advanced `shift` past 63, so the next iteration evaluated a left shift that violates Rust's shift precondition.

## Provenance

Verified and patched from the provided finding and reproducer. Scanner provenance: [Swival Security Scanner](https://swival.dev).

Confidence: certain.

## Preconditions

- A DWARF/LSDA stream contains an oversized SLEB128.
- The stream reaches `DwarfReader::read_sleb128`.
- The malformed encoding provides ten continuation bytes followed by another byte, e.g. `[0x80; 10]` followed by `0x00`.

## Proof

`read_sleb128` reads one byte per loop iteration via `self.read::<u8>()`, ORs the low seven bits into `result`, then increments `shift` by 7.

For an oversized SLEB128:

- After ten continuation bytes, `shift` reaches 70.
- The next loop iteration evaluates `((byte & 0x7F) as u64) << shift`.
- Because `shift > 63`, this violates the valid shift range for `u64`.
- A checked-build reproducer using `[0x80; 10]` followed by `0x00` panics with `attempt to shift left with overflow`.

The path is reachable through exception metadata parsing:

- `library/std/src/sys/personality/gcc.rs:325` obtains LSDA bytes from the unwinder.
- `library/std/src/sys/personality/gcc.rs:338` passes them into `eh::find_eh_action`.
- `library/std/src/sys/personality/dwarf/eh.rs:162` calls `read_sleb128()` for action-table `ttype_index`.
- `library/std/src/sys/personality/dwarf/eh.rs:203` calls `read_sleb128()` for `DW_EH_PE_sleb128` encoded offsets.

## Why This Is A Real Bug

The parser accepts DWARF bytes from LSDA/DWARF exception streams in loaded binaries or libraries. A malformed or hostile stream can therefore drive `read_sleb128` into an invalid oversized shift during unwinding.

In checked builds this traps or panics inside unwinding. In unchecked optimized builds it violates the parser invariant and can produce a misparsed value.

## Fix Requirement

Bound SLEB128 decoding to the width of the destination integer and stop before any shift count can exceed 63.

## Patch Rationale

The patch changes the loop exit condition from:

```rust
if byte & 0x80 == 0 {
    break;
}
```

to:

```rust
if byte & 0x80 == 0 || shift >= u64::BITS {
    break;
}
```

Because `shift` is incremented immediately after each safe shift, this guarantees the loop exits once 64-bit capacity has been reached. No later iteration can evaluate `u64 << shift` with `shift >= 64`.

This preserves normal SLEB128 decoding for valid encodings while preventing oversized encodings from violating the shift precondition.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/personality/dwarf/mod.rs b/library/std/src/sys/personality/dwarf/mod.rs
index 2bc91951b49..f9ce87ef5a6 100644
--- a/library/std/src/sys/personality/dwarf/mod.rs
+++ b/library/std/src/sys/personality/dwarf/mod.rs
@@ -56,7 +56,7 @@ pub unsafe fn read_sleb128(&mut self) -> i64 {
             byte = unsafe { self.read::<u8>() };
             result |= ((byte & 0x7F) as u64) << shift;
             shift += 7;
-            if byte & 0x80 == 0 {
+            if byte & 0x80 == 0 || shift >= u64::BITS {
                 break;
             }
         }
```