# Malformed Packet Type Accepted As Data

## Classification

Injection, medium severity, certain confidence.

## Affected Locations

`usr.sbin/ldomd/ds.c:585`

## Summary

`ds_receive_msg()` accepts packets as DS message data unless both the packet type and subtype are invalid. Because the rejection predicate uses `&&`, a non-data packet with `stype == LDC_INFO` is accepted and copied into the caller-provided DS receive buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The caller invokes `ds_receive_msg()` on an attacker-controlled LDC connection.
- The attacker can send crafted LDC packets on that connection.

## Proof

The vulnerable check is:

```c
if (lp.type != LDC_DATA &&
    lp.stype != LDC_INFO) {
	ldc_reset(lc);
	return;
}
```

This rejects only packets where both conditions are true. Therefore, a packet with:

```c
lp.type = LDC_CTRL;
lp.stype = LDC_INFO;
```

passes validation even though it is not `LDC_DATA`.

After that, `ds_receive_msg()` validates only the expected fragment-start state, then copies attacker-controlled bytes into the destination buffer:

```c
bcopy(&lp.data, p, (lp.env & LDC_LEN_MASK));
```

The issue is reachable from committed code: `pri_rx_data()` calls `ds_receive_msg()` for remaining PRI bytes after the first DS chunk. A malicious LDC peer can force this path with an oversized PRI payload, then send a `LDC_CTRL/LDC_INFO` packet with valid fragment flags. Its control-packet payload is treated as DS message bytes.

## Why This Is A Real Bug

`ds_receive_msg()` is a data receive path. It must accept only `LDC_DATA/LDC_INFO` packets. The current logic also accepts any packet with `stype == LDC_INFO`, including `LDC_CTRL/LDC_INFO`, which is semantically control traffic. That allows malformed control packets to inject bytes into DS message assembly instead of being rejected or handled by the control-plane parser.

## Fix Requirement

Reject the packet unless both conditions are true:

- `lp.type == LDC_DATA`
- `lp.stype == LDC_INFO`

## Patch Rationale

Changing the predicate from `&&` to `||` makes the guard reject if either field is wrong. This implements the intended allowlist: only packets that are both data packets and info subtyped are accepted by `ds_receive_msg()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomd/ds.c b/usr.sbin/ldomd/ds.c
index 0090a60..70fb3a2 100644
--- a/usr.sbin/ldomd/ds.c
+++ b/usr.sbin/ldomd/ds.c
@@ -581,7 +581,7 @@ ds_receive_msg(struct ldc_conn *lc, void *buf, size_t len)
 		if (nbytes != sizeof(lp))
 			err(1, "read");
 
-		if (lp.type != LDC_DATA &&
+		if (lp.type != LDC_DATA ||
 		    lp.stype != LDC_INFO) {
 			ldc_reset(lc);
 			return;
```