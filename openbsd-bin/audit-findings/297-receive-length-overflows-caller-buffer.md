# receive length overflows caller buffer

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`usr.sbin/ldomd/ds.c:596`

## Summary

`ds_receive_msg()` copies each attacker-controlled LDC packet payload into the caller-provided destination buffer without first checking that the packet length fits in the remaining buffer. A malicious LDC peer can set `lp.env & LDC_LEN_MASK` larger than the remaining `len`, causing `bcopy()` to write past the caller buffer.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller invokes `ds_receive_msg()` with a finite destination buffer.

## Proof

`ds_receive_msg()` reads an LDC packet directly from `lc->lc_fd` into `lp`, so the peer controls `lp.env`.

After validating only packet type and fragment-start state, the vulnerable code executes:

```c
bcopy(&lp.data, p, (lp.env & LDC_LEN_MASK));
p += (lp.env & LDC_LEN_MASK);
len -= (lp.env & LDC_LEN_MASK);
```

There is no pre-copy check that `(lp.env & LDC_LEN_MASK) <= len`.

The reproducer confirms practical reachability through `pri_rx_data()`: the PRI peer's declared `payload_len` determines the `pri_buf` allocation, and remaining bytes are received via `ds_receive_msg(lc, pri_buf + len, pri_len - len)`. A malicious LDC peer controlling `/dev/spds` traffic can make the first PRI data message leave 1 byte remaining, then send a packet with `LDC_FRAG_START | LDC_FRAG_STOP | 48`. The fragment-start check passes and `bcopy()` writes 48 bytes into a 1-byte remaining region, overrunning the heap allocation.

## Why This Is A Real Bug

The copy length is derived from untrusted packet metadata and is applied before reducing `len`. If the packet length exceeds the remaining caller buffer, the write crosses the destination boundary immediately. The later `len -= ...` cannot protect the buffer and may also underflow because `len` is unsigned.

## Fix Requirement

Reject any received packet whose payload length exceeds the remaining caller-provided buffer before calling `bcopy()`.

## Patch Rationale

The patch adds the required bounds check immediately after existing packet and fragment validation and before the copy:

```c
if ((lp.env & LDC_LEN_MASK) > len) {
	ldc_reset(lc);
	return;
}
```

This preserves normal behavior for valid fragments while resetting the connection and returning before any out-of-bounds write can occur for oversized fragments.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomd/ds.c b/usr.sbin/ldomd/ds.c
index 0090a60..e9f1203 100644
--- a/usr.sbin/ldomd/ds.c
+++ b/usr.sbin/ldomd/ds.c
@@ -592,6 +592,11 @@ ds_receive_msg(struct ldc_conn *lc, void *buf, size_t len)
 			return;
 		}
 
+		if ((lp.env & LDC_LEN_MASK) > len) {
+			ldc_reset(lc);
+			return;
+		}
+
 		bcopy(&lp.data, p, (lp.env & LDC_LEN_MASK));
 		p += (lp.env & LDC_LEN_MASK);
 		len -= (lp.env & LDC_LEN_MASK);
```