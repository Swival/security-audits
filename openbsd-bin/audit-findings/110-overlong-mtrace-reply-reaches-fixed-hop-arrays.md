# Overlong mtrace Reply Reaches Fixed Hop Arrays

## Classification

Memory corruption, high severity.

## Affected Locations

`usr.sbin/mtrace/mtrace.c:537`

## Summary

`send_recv()` accepted matching `IGMP_MTRACE_REPLY` packets containing more hop records than requested and more than the fixed `MAXHOPS` storage can hold. The overlong hop count was saved and the packet was copied into `struct resp_buf`, whose trace response array is fixed at `resps[MAXHOPS]`. Normal printing then iterated over the attacker-controlled length, causing out-of-bounds reads and writes in the `mtrace` process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The victim runs `mtrace` and accepts an attacker-controlled reply with a matching query id, source, and destination.

## Proof

A malicious multicast router can receive the victim’s mtrace query and send an `IGMP_MTRACE_REPLY` with `QLEN + 33 * RLEN` bytes of trace data.

Observed behavior:

- `send_recv()` validates the reply only for qid, source, destination, and record-size alignment.
- `len = (igmpdatalen - QLEN) / RLEN` can become 33.
- Before the patch, `len > code` only produced `Num hops received...` and processing continued.
- `struct resp_buf` stores only `resps[MAXHOPS]`; `MAXHOPS` is 32.
- `save->len = len` preserves the overlong value.
- `bcopy((char *)igmp, (char *)&save->igmp, ipdatalen)` copies the oversized trace data into fixed storage.
- The caller prints the accepted trace, and `print_trace()` loops through `buf->len`, reading past `resps[31]` and writing `names[32]` past `names[MAXHOPS]`.

This gives an attacker-controlled network packet that causes out-of-bounds memory access in `mtrace`.

## Why This Is A Real Bug

The code stores and trusts a hop count derived from packet length without enforcing either the requested hop limit or the fixed local array capacity. Because the packet contents come from the network and are copied into a fixed-size response buffer, an overlong reply directly crosses object bounds. The later `print_trace()` loop compounds this by using the unbounded saved length for array indexing into both `resps` and `names`.

## Fix Requirement

Reject mtrace replies when the decoded hop count exceeds either:

- the requested hop count, `code`
- the fixed response capacity, `MAXHOPS`

The rejection must happen before saving `len`, copying packet data into `struct resp_buf`, or calling code that iterates over the trace length.

## Patch Rationale

The patch adds an early bounds check immediately after decoding `len` from the reply length and after confirming the reply matches the outstanding query. If `len > code || len > MAXHOPS`, the packet is discarded with `continue`.

This prevents:

- storing an overlong `save->len`
- copying too many hop records into `resps[MAXHOPS]`
- later out-of-bounds reads from `resps`
- later out-of-bounds writes to `names`

The old diagnostic for `len > code` is preserved, but its behavior changes from warn-and-accept to warn-and-reject.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mtrace/mtrace.c b/usr.sbin/mtrace/mtrace.c
index 5fa9bf7..8171844 100644
--- a/usr.sbin/mtrace/mtrace.c
+++ b/usr.sbin/mtrace/mtrace.c
@@ -531,6 +531,12 @@ send_recv(u_int32_t dst, int type, int code, int tries, struct resp_buf *save)
 		if (rquery->tr_src != qsrc) continue;
 		if (rquery->tr_dst != qdst) continue;
 		len = (igmpdatalen - QLEN)/RLEN;
+		if (len > code || len > MAXHOPS) {
+		    fprintf(stderr,
+			    "Num hops received (%d) exceeds request (%d)\n",
+			    len, code);
+		    continue;
+		}
 
 		/*
 		 * Ignore trace queries passing through this node when
@@ -551,11 +557,6 @@ send_recv(u_int32_t dst, int type, int code, int tries, struct resp_buf *save)
 		/*
 		 * A match, we'll keep this one.
 		 */
-		if (len > code) {
-		    fprintf(stderr,
-			    "Num hops received (%d) exceeds request (%d)\n",
-			    len, code);
-		}
 		rquery->tr_raddr = query->tr_raddr;	/* Insure these are */
 		rquery->tr_rttl = query->tr_rttl;	/* as we sent them */
 		break;
```