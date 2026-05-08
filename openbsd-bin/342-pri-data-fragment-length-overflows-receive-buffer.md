# PRI_DATA fragment length overflows receive buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/ldomctl/pri.c:95`

## Summary

`pri_rx_data()` trusts the declared `PRI_DATA` `payload_len` for allocation size, but trusts the received DS fragment length for the initial copy size. A malicious LDC PRI peer can declare a small payload and send a larger fragment body, causing `bcopy()` to overwrite past the heap allocation before `ds_receive_msg()` is reached.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

`ldomctl` receives attacker-controlled `PRI_DATA` from an LDC peer.

## Proof

`ds_rx_msg()` dispatches `DS_DATA` to `pri_rx_data()` for the registered service handle through `usr.sbin/ldomd/ds.c:256`, `usr.sbin/ldomd/ds.c:261`, `usr.sbin/ldomd/ds.c:270`, `usr.sbin/ldomd/ds.c:482`, and `usr.sbin/ldomd/ds.c:490`.

In `pri_rx_data()`:

- `pd->payload_len - 24` is assigned to `pri_len`.
- `xmalloc(pri_len)` allocates the receive buffer.
- `len -= sizeof(struct pri_msg)` computes the already received fragment body length.
- `bcopy(&pd->data, pri_buf, len)` copies the actual fragment body without checking `len <= pri_len`.

Concrete trigger:

- Send `DS_DATA` with `type = PRI_DATA`.
- Set `payload_len = 25`.
- Send an assembled LDC message length of 80 bytes.

This makes `pri_len = 1`, allocates 1 byte, then copies 48 bytes into that allocation.

A small ASan harness using the committed `pri_rx_data()` logic reports `heap-buffer-overflow`, `WRITE of size 48`, at the `bcopy()` into the 1-byte allocation.

## Why This Is A Real Bug

The vulnerable code allocates from the declared payload length but copies from the actual received message length. Those values are independently attacker-controlled through the PRI/DS message. When the received fragment body is larger than the declared PRI payload, the copy exceeds the heap buffer. The overflow occurs immediately in `bcopy()` and does not depend on later parsing or `ds_receive_msg()` behavior.

## Fix Requirement

Reject malformed `PRI_DATA` messages where:

- `payload_len < 24`, because subtracting 24 would underflow.
- The received fragment body length exceeds the declared PRI payload length.

## Patch Rationale

The patch validates the declared payload length before subtracting the PRI header contribution, preventing unsigned underflow. It then computes the received fragment body length and rejects messages where that body is larger than the allocated PRI receive buffer. Allocation is moved after validation so malformed inputs do not allocate buffers that will not be used.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/pri.c b/usr.sbin/ldomctl/pri.c
index 94d8bb1..287d116 100644
--- a/usr.sbin/ldomctl/pri.c
+++ b/usr.sbin/ldomctl/pri.c
@@ -88,10 +88,14 @@ pri_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data, size_t len)
 		return;
 	}
 
+	if (pd->payload_len < 24)
+		return;
 	pri_len = pd->payload_len - 24;
-	pri_buf = xmalloc(pri_len);
 
 	len -= sizeof(struct pri_msg);
+	if (len > pri_len)
+		return;
+	pri_buf = xmalloc(pri_len);
 	bcopy(&pd->data, pri_buf, len);
 	ds_receive_msg(lc, pri_buf + len, pri_len - len);
 }
```