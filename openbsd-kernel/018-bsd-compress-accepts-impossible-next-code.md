# BSD-Compress accepts impossible next code

## Classification

denial of service, medium severity, confidence certain

## Affected Locations

`net/bsd-comp.c:912`

## Summary

The BSD-Compress decompressor accepts `incode == max_ent + 2`, although the only valid lookahead code above the current dictionary is `max_ent + 1` for the LZW KwKwK case. A remote PPP peer can use that impossible code to corrupt decompressor dictionary state and later trigger an unbounded chain walk, causing a hang or memory corruption in a normal non-`DEBUG` kernel.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

BSD-Compress decompression is negotiated with the remote PPP peer.

## Proof

The vulnerable validation in `bsd_decompress` rejects only codes greater than `max_ent + 2`:

```c
if (incode > max_ent + 2 || incode > db->maxmaxcode
    || (incode > max_ent && oldcode == CLEAR)) {
```

This incorrectly permits `incode == max_ent + 2`.

A peer can first initialize `lens[258]` with valid codes `0x21, 0x41, 0x42`, then append an end-of-packet `CLEAR`. `bsd_clear` resets `max_ent` but does not clear `lens`, so stale length state remains available after the reset.

The next compressed frame with 9-bit codes `0x21, 0x102, 0x41, 0x102` then exercises the impossible-code path:

- `0x102` is `max_ent + 2` after reset and is accepted.
- The code enters the KwKwK branch because `incode > max_ent`.
- The impossible `incode` is saved as `oldcode`.
- The following allocation computes `db->lens[max_ent] = db->lens[oldcode] + 1` using a code that is not valid in the current dictionary.
- This makes code 258 self-referential with a small length.
- Decoding that self-referential code reaches the `while (finchar > LAST)` chain walk, where `finchar` remains 258 and `*--p` writes backward repeatedly.

Result: remote PPP input can hang the decompressor or corrupt memory after BSD-Compress negotiation.

## Why This Is A Real Bug

The decompressor has only one valid above-dictionary exception: the LZW KwKwK case, where the next code may equal `max_ent + 1`. Accepting `max_ent + 2` is outside the format semantics and creates dictionary state that cannot be produced by a valid compressor.

The reproduced sequence demonstrates that this is not merely malformed input being rejected late. The invalid code is accepted, stored as `oldcode`, and used in later dictionary length accounting, producing a reachable self-referential chain and practical denial of service.

## Fix Requirement

Reject any input code greater than `max_ent + 1` before entering the KwKwK handling path.

## Patch Rationale

The patch changes the validation bound from `max_ent + 2` to `max_ent + 1`:

```diff
-	if (incode > max_ent + 2 || incode > db->maxmaxcode
+	if (incode > max_ent + 1 || incode > db->maxmaxcode
```

This preserves the valid KwKwK lookahead case while rejecting the impossible `max_ent + 2` code before it can be saved as `oldcode` or used to derive dictionary length state.

## Residual Risk

None

## Patch

`018-bsd-compress-accepts-impossible-next-code.patch`

```diff
diff --git a/net/bsd-comp.c b/net/bsd-comp.c
index 1edb6a6..6cae7f7 100644
--- a/net/bsd-comp.c
+++ b/net/bsd-comp.c
@@ -909,7 +909,7 @@ bsd_decompress(void *state, struct mbuf *cmp, struct mbuf **dmpp)
 	    break;
 	}
 
-	if (incode > max_ent + 2 || incode > db->maxmaxcode
+	if (incode > max_ent + 1 || incode > db->maxmaxcode
 	    || (incode > max_ent && oldcode == CLEAR)) {
 	    m_freem(mret);
 	    if (db->debug) {
```