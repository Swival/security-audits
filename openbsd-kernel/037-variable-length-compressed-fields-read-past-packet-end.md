# variable-length compressed fields read past packet end

## Classification

High severity out-of-bounds read in VJ TCP decompression.

## Affected Locations

`net/slcompress.c:136`

## Summary

`sl_uncompress_tcp_core()` decodes peer-supplied compressed TCP fields before verifying that the compressed packet still contains enough bytes. For long-form delta encodings, the `DECODEL`, `DECODES`, and `DECODEU` macros read `cp[1]` and `cp[2]` when `*cp == 0`. A truncated compressed frame can end at the zero marker, causing the kernel to read past the received packet buffer before the later `buflen` check rejects the packet.

## Provenance

Confirmed from the supplied source, reproduced trigger, and patch. Scanner provenance: [Swival Security Scanner](https://swival.dev).

Confidence: certain.

## Preconditions

- VJ TCP decompression is enabled.
- `sl_uncompress_tcp_core()` processes peer-supplied `TYPE_COMPRESSED_TCP` frames.
- The peer can send a truncated compressed TCP frame.

## Proof

A minimal reproduced frame is:

```text
42 00 12 34 00
```

Interpretation:

- `0x42` sets `NEW_C | NEW_W`.
- CID `0x00` is valid and selects explicit state via `NEW_C`.
- `0x12 0x34` provides the TCP checksum.
- Final `0x00` is the long-form delta marker for `NEW_W`, but the two following bytes are missing.

Execution path:

- `TYPE_COMPRESSED_TCP` sets `cp = buf`.
- `NEW_C` consumes the explicit state id and clears `SLF_TOSS`, so no prior VJ state is required for this trigger.
- Checksum parsing consumes two bytes.
- `NEW_W` dispatches to `DECODES(th->th_win)`.
- `DECODES` sees `*cp == 0` and immediately reads `cp[1]` and `cp[2]`.
- Only after decoding does the function compute `vjlen = cp - buf`, subtract it from `buflen`, and reject if negative.

Thus the packet is rejected only after the out-of-bounds read has already occurred.

## Why This Is A Real Bug

The compressed packet is attacker-controlled input from an untrusted PPP/VJ peer. The decoder advances through variable-length fields without checking remaining packet length before each dereference. The later `buflen < 0` validation does not protect the earlier reads. This is a remotely triggerable kernel memory-safety violation with denial-of-service potential.

## Fix Requirement

Validate the remaining compressed-buffer length before every read from `cp`, including:

- The initial change byte.
- The optional explicit connection id.
- The two-byte checksum.
- Each one-byte or three-byte compressed delta field decoded by `DECODEL`, `DECODES`, and `DECODEU`.

## Patch Rationale

The patch introduces an end pointer, `ep = buf + buflen`, and checks `cp` against `ep` before each compressed-header read.

Key changes:

- Reject empty compressed packets before reading `changes`.
- Validate the explicit CID byte before reading it.
- Validate the checksum has two bytes before reading `cp[0]` and `cp[1]`.
- Update `DECODEL`, `DECODES`, and `DECODEU` to reject when no byte remains.
- For long-form fields, require at least three bytes before reading `cp[1]` and `cp[2]`.

This moves validation before the vulnerable dereferences while preserving the existing `bad` error path and `SLF_TOSS` behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/net/slcompress.c b/net/slcompress.c
index 12907da..ca565ed 100644
--- a/net/slcompress.c
+++ b/net/slcompress.c
@@ -136,7 +136,11 @@ sl_compress_setup(struct slcompress *comp, int max_state)
 }
 
 #define DECODEL(f) { \
+	if (cp >= ep) \
+		goto bad; \
 	if (*cp == 0) {\
+		if (ep - cp < 3) \
+			goto bad; \
 		(f) = htonl(ntohl(f) + ((cp[1] << 8) | cp[2])); \
 		cp += 3; \
 	} else { \
@@ -145,7 +149,11 @@ sl_compress_setup(struct slcompress *comp, int max_state)
 }
 
 #define DECODES(f) { \
+	if (cp >= ep) \
+		goto bad; \
 	if (*cp == 0) {\
+		if (ep - cp < 3) \
+			goto bad; \
 		(f) = htons(ntohs(f) + ((cp[1] << 8) | cp[2])); \
 		cp += 3; \
 	} else { \
@@ -154,7 +162,11 @@ sl_compress_setup(struct slcompress *comp, int max_state)
 }
 
 #define DECODEU(f) { \
+	if (cp >= ep) \
+		goto bad; \
 	if (*cp == 0) {\
+		if (ep - cp < 3) \
+			goto bad; \
 		(f) = htons((cp[1] << 8) | cp[2]); \
 		cp += 3; \
 	} else { \
@@ -463,7 +475,7 @@ int
 sl_uncompress_tcp_core(u_char *buf, int buflen, int total_len, u_int type,
     struct slcompress *comp, u_char **hdrp, u_int *hlenp)
 {
-	u_char *cp;
+	u_char *cp, *ep;
 	u_int hlen, changes;
 	struct tcphdr *th;
 	struct cstate *cs;
@@ -506,11 +518,14 @@ sl_uncompress_tcp_core(u_char *buf, int buflen, int total_len, u_int type,
 	/* We've got a compressed packet. */
 	INCR(sls_compressedin)
 	cp = buf;
+	ep = buf + buflen;
+	if (cp >= ep)
+		goto bad;
 	changes = *cp++;
 	if (changes & NEW_C) {
 		/* Make sure the state index is in range, then grab the state.
 		 * If we have a good state index, clear the 'discard' flag. */
-		if (*cp >= MAX_STATES)
+		if (cp >= ep || *cp >= MAX_STATES)
 			goto bad;
 
 		comp->flags &=~ SLF_TOSS;
@@ -527,6 +542,8 @@ sl_uncompress_tcp_core(u_char *buf, int buflen, int total_len, u_int type,
 	cs = &comp->rstate[comp->last_recv];
 	hlen = cs->cs_ip.ip_hl << 2;
 	th = (struct tcphdr *)&((u_char *)&cs->cs_ip)[hlen];
+	if (ep - cp < 2)
+		goto bad;
 	th->th_sum = htons((*cp << 8) | cp[1]);
 	cp += 2;
 	if (changes & TCP_PUSH_BIT)
```