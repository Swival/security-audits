# Unchecked Call-Site Table Length Pointer Add

## Classification

High severity validation gap causing undefined behavior on malformed DWARF LSDA input.

## Affected Locations

`library/std/src/sys/personality/dwarf/eh.rs:93`

## Summary

`find_eh_action` reads `call_site_table_length` from attacker-controlled or malformed LSDA bytes and uses it to compute `action_table`. The original code performed `reader.ptr.add(call_site_table_length as usize)` without validating conversion or address overflow. A malformed oversized length can therefore create an out-of-allocation pointer through `ptr.add`, which is undefined behavior before later parsing can reject the LSDA.

## Provenance

Reported and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- A malformed LSDA is supplied to `find_eh_action`.
- The LSDA encodes an oversized `call_site_table_length`.
- `DwarfReader` has no tracked LSDA end pointer or allocation length.

## Proof

LSDA bytes enter `find_eh_action` through `lsda` and are consumed by `DwarfReader`.

`DwarfReader` stores only a current pointer, with no end pointer or allocation length. In `find_eh_action`, `call_site_table_length` is read from the LSDA via `read_uleb128`, then immediately used to compute the action table pointer.

A concrete malformed LSDA such as:

```text
[0xff, 0xff, 0x01, 0x80, 0x80, 0x04]
```

encodes:

- omitted landing-pad base
- omitted type table
- ULEB128 call-site encoding
- `call_site_table_length = 65536`

After these bytes are read, `reader.ptr` is already one-past the 6-byte LSDA allocation. The original `reader.ptr.add(65536)` computes a pointer far outside the same allocation. `ptr.add` requires the result to remain in-bounds or one-past the same allocation, so this is undefined behavior at the action-table calculation itself.

## Why This Is A Real Bug

The bug occurs before any later call-site table parsing, pointer comparison, read, or error return. The invalid pointer is created directly by `ptr.add`, whose safety contract is stricter than integer address arithmetic. Because the LSDA length is untrusted and no LSDA allocation bounds are tracked, malformed input can violate the `ptr.add` in-allocation requirement during unwinding.

If execution continues after the invalid computation, the bogus `action_table` also influences subsequent table parsing and action-record reads, increasing the risk of out-of-bounds parsing, crash, or incorrect unwind classification.

## Fix Requirement

The code must reject invalid call-site table lengths before creating an invalid pointer. Specifically, it must avoid unchecked `ptr.add` with untrusted LSDA length data and must handle integer conversion and address overflow safely.

## Patch Rationale

The patch replaces provenance-sensitive `ptr.add` with checked integer address arithmetic:

```rust
let call_site_table_length = usize::try_from(reader.read_uleb128()).map_err(|_| ())?;
let action_table_addr = reader.ptr.addr().checked_add(call_site_table_length).ok_or(())?;
reader.ptr.with_addr(action_table_addr)
```

This fixes two concrete issues:

- rejects `u64` LSDA lengths that do not fit in `usize`
- rejects address arithmetic overflow before constructing the pointer address

Using `with_addr` avoids the immediate `ptr.add` same-allocation UB caused by a malformed length. The function now returns `Err(())` for unrepresentable or overflowing lengths instead of invoking undefined behavior during pointer addition.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/personality/dwarf/eh.rs b/library/std/src/sys/personality/dwarf/eh.rs
index ef5112ad74f..d9c620f7ebf 100644
--- a/library/std/src/sys/personality/dwarf/eh.rs
+++ b/library/std/src/sys/personality/dwarf/eh.rs
@@ -89,8 +89,9 @@ pub unsafe fn find_eh_action(lsda: *const u8, context: &EHContext<'_>) -> Result
         reader.read::<u8>()
     };
     let action_table = unsafe {
-        let call_site_table_length = reader.read_uleb128();
-        reader.ptr.add(call_site_table_length as usize)
+        let call_site_table_length = usize::try_from(reader.read_uleb128()).map_err(|_| ())?;
+        let action_table_addr = reader.ptr.addr().checked_add(call_site_table_length).ok_or(())?;
+        reader.ptr.with_addr(action_table_addr)
     };
     let ip = context.ip;
```