# AS4_PATH merge wraps heap allocation length

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/bgpd/rde_attr.c:481`

## Summary

`aspath_merge()` computes the merged AS path length in a `uint16_t`. A malicious peer can provide AS_PATH and AS4_PATH attributes whose combined merge length exceeds `UINT16_MAX`, causing `nlen` to wrap before `malloc(nlen)`. The subsequent copy operations use the unwrapped component lengths and write past the undersized heap allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an ASan harness using the committed `aspath_merge()` logic.

## Preconditions

- Attacker controls an established BGP peer.
- The peer can send a BGP UPDATE containing AS_PATH and AS4_PATH attributes.
- The negotiated/session state reaches AS4_PATH merge handling.

## Proof

`aspath_merge()` computes:

```c
difflen = aspath_countlength(a->aspath, diff, hroom);
nlen = attr->len + difflen;
np = malloc(nlen);
aspath_countcopy(a->aspath, diff, np, difflen, hroom);
memcpy(... attr->len ...);
```

Both `attr->len` and `difflen` are `uint16_t`, and the original `nlen` is also `uint16_t`.

The reproduced case used:

- AS_PATH wire length: 26,320 bytes.
- AS_PATH internal inflated length: 52,536 bytes.
- AS4_PATH length: 39,172 bytes.
- Computed `diff`: 6,579.
- Computed `difflen`: 26,366.
- Actual merged length: `39,172 + 26,366 = 65,538`.
- Wrapped `uint16_t nlen`: `2`.

Runtime ASan confirmation showed:

```text
attr_len=39172 difflen=26366 uint16_nlen=2 actual_sum=65538
heap-buffer-overflow writing 1022 bytes into the 2-byte allocation during aspath_countcopy
```

## Why This Is A Real Bug

The allocation size is derived from a wrapped 16-bit sum, while the writes are derived from the original AS_PATH and AS4_PATH component lengths. This creates a reachable size mismatch: `malloc(2)` can be followed by a copy of at least 1,022 bytes in the reproduced case.

The input is attacker-controlled through BGP UPDATE attributes from a malicious peer. The result is route decision engine heap corruption, producing at least denial of service and potentially stronger memory-corruption impact.

## Fix Requirement

Compute the merged length in a type wide enough to represent the sum, and reject merged AS_PATH lengths above `UINT16_MAX` before allocation or copy.

## Patch Rationale

The patch changes `nlen` from `uint16_t` to `size_t` and casts `attr->len` before addition:

```c
nlen = (size_t)attr->len + difflen;
```

It then rejects overlarge merged paths:

```c
if (nlen > UINT16_MAX) {
	attr_free(a, attr);
	return;
}
```

This prevents truncation before `malloc()` and preserves the existing function contract that AS path lengths fit in the 16-bit length field used by `aspath_get()` and attribute serialization.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/rde_attr.c b/usr.sbin/bgpd/rde_attr.c
index 56d0eb1..0b28541 100644
--- a/usr.sbin/bgpd/rde_attr.c
+++ b/usr.sbin/bgpd/rde_attr.c
@@ -459,7 +459,8 @@ void
 aspath_merge(struct rde_aspath *a, struct attr *attr)
 {
 	uint8_t		*np;
-	uint16_t	 ascnt, diff, nlen, difflen;
+	size_t		 nlen;
+	uint16_t	 ascnt, diff, difflen;
 	int		 hroom = 0;
 
 	ascnt = aspath_count(attr->data, attr->len);
@@ -473,7 +474,11 @@ aspath_merge(struct rde_aspath *a, struct attr *attr)
 	if (diff && attr->len > 2 && attr->data[0] == AS_SEQUENCE)
 		hroom = attr->data[1];
 	difflen = aspath_countlength(a->aspath, diff, hroom);
-	nlen = attr->len + difflen;
+	nlen = (size_t)attr->len + difflen;
+	if (nlen > UINT16_MAX) {
+		attr_free(a, attr);
+		return;
+	}
 
 	if ((np = malloc(nlen)) == NULL)
 		fatal("%s", __func__);
```