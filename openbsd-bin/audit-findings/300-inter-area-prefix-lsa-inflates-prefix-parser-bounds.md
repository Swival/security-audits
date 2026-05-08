# inter-area prefix LSA inflates prefix parser bounds

## Classification

High severity out-of-bounds read.

## Affected Locations

`usr.sbin/ospf6d/rde_lsdb.c:251`

## Summary

`lsa_check()` validates `LSA_TYPE_INTER_A_PREFIX` by parsing the prefix located after the LSA header and prefix-summary body. The pointer passed to `lsa_get_prefix()` is advanced past both fixed-size structures, but the remaining-length argument incorrectly adds the prefix-summary size instead of subtracting it. A minimal valid-length Inter-Area-Prefix LSA can therefore make `lsa_get_prefix()` believe bytes remain and read past the received LSA allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Malicious OSPFv3 neighbor can send an LS Update accepted in neighbor state `XCHNG`, `LOAD`, or `FULL`.
- LSA has a valid checksum.
- LSA has an acceptable age, sequence number, and metric.
- LSA length is exactly `sizeof(struct lsa_hdr) + sizeof(struct lsa_prefix_sum)`.

## Proof

LS Update processing forwards exactly the advertised LSA length to RDE. RDE allocates exactly that length before invoking `lsa_check()`.

For a 24-byte Inter-Area-Prefix LSA:

- `sizeof(struct lsa_hdr) == 20`
- `sizeof(struct lsa_prefix_sum) == 4`
- `len == 24`

`lsa_check()` first accepts the fixed-size LSA because:

```c
len >= sizeof(lsa->hdr) + sizeof(lsa->data.pref_sum)
```

It then calls:

```c
lsa_get_prefix(((char *)lsa) + sizeof(lsa->hdr) +
    sizeof(lsa->data.pref_sum),
    len - sizeof(lsa->hdr) + sizeof(lsa->data.pref_sum),
    NULL)
```

The pointer is `lsa + 24`, one byte past the allocation. The length argument evaluates to:

```c
24 - 20 + 4 == 8
```

The correct remaining length is:

```c
24 - 20 - 4 == 0
```

Because `lsa_get_prefix()` receives `len == 8`, its initial size check at `usr.sbin/ospf6d/rde_lsdb.c:985` does not reject the buffer, and it reads `lp->prefixlen` at `usr.sbin/ospf6d/rde_lsdb.c:988` from beyond the received LSA.

A small ASan harness using the same logic with a valid computed LSA checksum aborts on this heap-buffer-overflow.

## Why This Is A Real Bug

The parser’s pointer and bound disagree. The pointer is advanced past the fixed Inter-Area-Prefix summary, but the bound is inflated by adding that summary size back. The preceding minimum-length check only proves the fixed summary exists; it does not prove any prefix bytes exist. Therefore a syntactically minimal LSA can pass earlier validation and trigger an out-of-bounds read during prefix validation.

## Fix Requirement

Pass the actual number of bytes remaining after the LSA header and prefix-summary body:

```c
len - sizeof(lsa->hdr) - sizeof(lsa->data.pref_sum)
```

## Patch Rationale

The patch changes only the length argument supplied to `lsa_get_prefix()` for `LSA_TYPE_INTER_A_PREFIX`. This makes the buffer pointer and buffer length describe the same region: the bytes after the fixed prefix-summary structure. A minimal 24-byte LSA now passes a remaining length of `0`, causing `lsa_get_prefix()` to reject it before dereferencing `lp->prefixlen`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ospf6d/rde_lsdb.c b/usr.sbin/ospf6d/rde_lsdb.c
index 33b6b69..3572765 100644
--- a/usr.sbin/ospf6d/rde_lsdb.c
+++ b/usr.sbin/ospf6d/rde_lsdb.c
@@ -249,7 +249,7 @@ lsa_check(struct rde_nbr *nbr, struct lsa *lsa, u_int16_t len)
 		}
 		if (lsa_get_prefix(((char *)lsa) + sizeof(lsa->hdr) +
 		    sizeof(lsa->data.pref_sum),
-		    len - sizeof(lsa->hdr) + sizeof(lsa->data.pref_sum),
+		    len - sizeof(lsa->hdr) - sizeof(lsa->data.pref_sum),
 		    NULL) == -1) {
 			log_warnx("lsa_check: "
 			    "invalid LSA prefix summary packet");
```