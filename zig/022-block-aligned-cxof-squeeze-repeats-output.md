# Block-Aligned CXOF Squeeze Repeats Output

## Classification

Cryptographic flaw. Severity: high. Confidence: certain.

## Affected Locations

- `lib/std/crypto/ascon.zig:936`
- Function: `AsconCxof128.squeeze`

## Summary

`AsconCxof128.squeeze` can repeat the previous 8-byte output block when called incrementally and the prior call ended exactly on an 8-byte block boundary. The state is only permuted when more bytes remain in the same call, so a subsequent `squeeze` starts from the same state word and emits duplicate XOF bytes instead of continuing the stream.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Caller uses the public `AsconCxof128.squeeze` API incrementally.
- The first or any prior `squeeze` call emits an output length aligned to the 8-byte CXOF rate.

## Proof

The vulnerable loop writes `self.st.st[0]` to the caller buffer, advances `i`, and only permutes when `i < out.len`.

For an 8-byte output request:

```text
first  squeeze(8): 5d3917b2b138ceed
second squeeze(8): 5d3917b2b138ceed
equal: true

one-shot squeeze(16): 5d3917b2b138ceed173d5885976143e6
```

The second incremental squeeze repeats the first block instead of producing the next stream block, which should be `173d5885976143e6` in this reproduction.

## Why This Is A Real Bug

`AsconCxof128.squeeze` is public and documented as callable multiple times to generate more output. A caller-controlled chunking pattern changes the output stream and can cause repeated pseudorandom output. XOF output must be continuous across incremental squeeze calls; repeating a block violates the API contract and weakens cryptographic consumers that depend on unique stream bytes.

## Fix Requirement

Advance the CXOF state after every full 8-byte block is emitted so that any later `squeeze` call starts at the next XOF stream block.

## Patch Rationale

Changing the permutation condition from `i < out.len` to `to_copy == 8` ensures the state is advanced whenever a complete rate block is emitted, including the final block of a call. Partial final blocks are not advanced, preserving the current state for any future continuation from that partial block boundary.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/ascon.zig b/lib/std/crypto/ascon.zig
index 3142bc0a89..371d24d2cf 100644
--- a/lib/std/crypto/ascon.zig
+++ b/lib/std/crypto/ascon.zig
@@ -928,7 +928,7 @@ pub const AsconCxof128 = struct {
             @memcpy(out[i..][0..to_copy], block[0..to_copy]);
             i += to_copy;
 
-            if (i < out.len) {
+            if (to_copy == 8) {
                 self.st.permuteR(12);
             }
         }
```