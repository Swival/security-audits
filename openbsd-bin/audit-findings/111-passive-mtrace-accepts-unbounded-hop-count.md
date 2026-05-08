# passive mtrace accepts unbounded hop count

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/mtrace/mtrace.c:656`

## Summary

`mtrace` passive mode accepts IGMP mtrace query/reply packets with more than `MAXHOPS` hop records. The computed hop count is stored in `base.len` and the full packet body is copied into fixed-size trace storage, corrupting memory when an attacker supplies `MAXHOPS + 1` or more records.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and patch evidence.

## Preconditions

- `mtrace` runs in passive mode, such as `mtrace -p`.
- A remote multicast-reachable host can send IGMP mtrace query/reply packets to the passive listener.
- The packet is structurally aligned as `QLEN + n * RLEN`, with `n > MAXHOPS`.

## Proof

In `passive_mode()`, IGMP mtrace packets are accepted after only minimum query length and record alignment checks:

```c
if (igmpdatalen < QLEN) continue;
if ((igmpdatalen - QLEN)%RLEN) {
    printf("packet with incorrect datalen\n");
    continue;
}

len = (igmpdatalen - QLEN)/RLEN;
```

Before the patch, `len` was not capped to `MAXHOPS`.

The reproduced trigger uses 33 hop records where `MAXHOPS` is 32:

- `ipdatalen = IGMP_MINLEN + QLEN + 33 * RLEN = 1080`
- fixed destination trace storage holds only `IGMP_MINLEN + QLEN + 32 * RLEN = 1048`

The unchecked packet is copied here:

```c
base.len = len;
bcopy((char *)igmp, (char *)&base.igmp, ipdatalen);
```

This writes the 33rd record past `base` before optional `qsrc`/`qdst`/`qgrp` filtering.

The corrupted length is then used by:

```c
print_trace(1, &base);
```

`print_trace()` iterates to `buf->len`, causing out-of-bounds reads from `resps[MAXHOPS]` and writes past `names[MAXHOPS]`.

## Why This Is A Real Bug

The packet size is valid for the receive buffer but invalid for the destination object. `RECV_BUF_SIZE` is 8192, while `base.igmp` plus the trace union only has room for `MAXHOPS` response records. Therefore a validly received IGMP packet with `MAXHOPS + 1` aligned records deterministically overflows fixed process memory.

The impact is attacker-triggered memory corruption in the passive `mtrace` process, with practical denial-of-service risk.

## Fix Requirement

Passive mtrace handling must reject or safely truncate packets whose computed hop count exceeds `MAXHOPS` before copying packet data into `base` and before using the length for trace printing.

## Patch Rationale

The patch rejects oversized passive mtrace packets immediately after computing the hop count:

```c
len = (igmpdatalen - QLEN)/RLEN;
if (len > MAXHOPS)
    continue;
```

This preserves normal handling for valid packets and prevents both the initial out-of-bounds write into `base` and the later out-of-bounds accesses in `print_trace()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mtrace/mtrace.c b/usr.sbin/mtrace/mtrace.c
index 5fa9bf7..aee0786 100644
--- a/usr.sbin/mtrace/mtrace.c
+++ b/usr.sbin/mtrace/mtrace.c
@@ -654,6 +654,8 @@ passive_mode(void)
 	    }
 
 	    len = (igmpdatalen - QLEN)/RLEN;
+	    if (len > MAXHOPS)
+		continue;
 
 	    break;
```