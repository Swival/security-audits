# Block-Aligned Ascon-XOF128 Squeeze Repeats Output

## Classification

- Type: cryptographic flaw
- Severity: high
- Confidence: certain

## Affected Locations

- `lib/std/crypto/ascon.zig:768`
- Function: `AsconXof128.squeeze`

## Summary

`AsconXof128.squeeze` failed to advance the permutation state after emitting an exactly 8-byte-aligned output chunk. A subsequent `squeeze` call therefore emitted the same `self.st.st[0]` block again instead of continuing the XOF stream.

## Provenance

Verified from the supplied reproducer and patch material.

Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- An application exposes consecutive Ascon-XOF128 output.
- An attacker can influence XOF output chunk sizes.
- The attacker can cause an 8-byte-aligned `squeeze` followed by another `squeeze`.

## Proof

Minimal reproduced sequence:

```zig
var xof = ascon.AsconXof128.init(.{});
xof.update("");

var a: [8]u8 = undefined;
var b: [8]u8 = undefined;
xof.squeeze(&a);
xof.squeeze(&b);
```

Observed output:

```text
473D5E6164F58B39
473D5E6164F58B39
```

The official committed empty-message 64-byte Ascon-XOF128 test vector begins:

```text
473D5E6164F58B39 DFD84AACDB8AE42E ...
```

Therefore, for the same XOF stream, the second 8-byte chunk should be:

```text
DFD84AACDB8AE42E
```

not a repeat of the first block.

The root cause is that `squeeze` only called `self.st.permuteR(12)` when `i < out.len`. For an exactly block-aligned output request, `i == out.len` after the final emitted block, so the state was not advanced before the next public `squeeze` call.

## Why This Is A Real Bug

XOF output must be chunking-invariant: requesting output as one 16-byte squeeze or as two 8-byte squeezes must produce the same continuous stream. The implementation violated this invariant through the public streaming API.

Under the stated precondition, an untrusted peer can force repeated XOF stream blocks, causing duplicated output where the application expects fresh pseudorandom bytes.

## Fix Requirement

Advance or otherwise track the XOF state after every fully consumed output block, including the final block of a block-aligned `squeeze` call.

## Patch Rationale

The patch changes the permutation condition from “more bytes remain in this call” to “a full 8-byte block was consumed.”

This ensures that after emitting a complete XOF block, the internal state is advanced immediately, so the next `squeeze` call continues from the correct stream position.

Partial final blocks are not permuted immediately, preserving the existing behavior for partially consumed blocks.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/ascon.zig b/lib/std/crypto/ascon.zig
index 3142bc0a89..ca4c2a0eba 100644
--- a/lib/std/crypto/ascon.zig
+++ b/lib/std/crypto/ascon.zig
@@ -776,7 +776,7 @@ pub const AsconXof128 = struct {
             @memcpy(out[i..][0..to_copy], block[0..to_copy]);
             i += to_copy;
 
-            if (i < out.len) {
+            if (to_copy == block_length) {
                 self.st.permuteR(12);
             }
         }
```