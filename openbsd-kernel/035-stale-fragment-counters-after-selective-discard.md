# Stale Fragment Counters After Selective Discard

## Classification

Denial of service, medium severity.

## Affected Locations

`netinet6/frag6.c:279`

## Summary

`frag6_input()` can remove previously queued IPv6 fragments during offset-zero fragment processing without decrementing the global and per-queue fragment counters. A remote IPv6 sender can make `frag6_nfrags` remain artificially exhausted, causing later fragmented IPv6 traffic to be dropped at the global fragment limit check.

## Provenance

Verified and reproduced from the supplied finding.

Scanner provenance: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

IPv6 fragment reassembly is enabled with finite `ip6_maxfrags`.

## Proof

`frag6_input()` accepts non-first fragments before the offset-zero fragment has arrived. On insertion, it increments both counters:

```c
frag6_nfrags++;
q6->ip6q_nfrag++;
```

When the offset-zero fragment later arrives, `q6->ip6q_unfrglen` becomes known. The `fragoff == 0` loop then checks already stored fragments:

```c
if (q6->ip6q_unfrglen + af6->ip6af_off +
    af6->ip6af_frglen > IPV6_MAXPACKET) {
```

For oversized stored fragments, the code removes and frees `af6`:

```c
LIST_REMOVE(af6, ip6af_list);
pool_put(&ip6af_pool, af6);
```

Before the patch, this path did not decrement `frag6_nfrags` or `q6->ip6q_nfrag`.

A practical trigger is:

1. Send valid tail non-first fragments ending near `65535` before any first fragment.
2. Send an offset-zero fragment with `M=1` and a large Destination Options header before the Fragment header.
3. The tail fragments become oversized once `q6->ip6q_unfrglen` is recorded.
4. The loop frees those fragments but leaves both counters stale.
5. The current first fragment is inserted and increments the counters again.
6. Once stale `frag6_nfrags` reaches `ip6_maxfrags`, the entry check drops later fragments before queue lookup.

The dropping check is:

```c
if (frag6_nfrags >= atomic_load_int(&ip6_maxfrags)) {
	mtx_leave(&frag6_mutex);
	goto dropfrag;
}
```

## Why This Is A Real Bug

The removed fragments no longer exist in `q6->ip6q_asfrag`, but they remain accounted in `frag6_nfrags` and `q6->ip6q_nfrag`.

This violates the counter invariant used by the reassembly limit enforcement. Because the limit is checked before queue lookup, stale global accounting denies unrelated future fragmented IPv6 reassembly traffic until the affected queue completes, is flushed, or expires through `frag6_slowtimo()`.

The impact is remotely triggerable by crafted IPv6 fragments sent to local reassembly.

## Fix Requirement

When selectively discarding a stored fragment from `q6->ip6q_asfrag`, decrement:

- `frag6_nfrags`
- `q6->ip6q_nfrag`

The decrement must occur while `frag6_mutex` is held and in the same path that removes the fragment from the list.

## Patch Rationale

The patch restores accounting symmetry.

Fragments inserted into the queue increment both counters. The selective discard path removes exactly one queued fragment, so it must decrement exactly those same counters before freeing the fragment metadata.

This keeps:

- `frag6_nfrags` equal to the number of queued fragments globally.
- `q6->ip6q_nfrag` equal to the number of fragments in the reassembly queue.
- Existing later cleanup paths correct, because they subtract only the remaining queued fragment count.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet6/frag6.c b/netinet6/frag6.c
index a6692a4..5ff6882 100644
--- a/netinet6/frag6.c
+++ b/netinet6/frag6.c
@@ -273,6 +273,8 @@ frag6_input(struct mbuf **mp, int *offp, int proto, int af,
 
 				/* dequeue the fragment. */
 				LIST_REMOVE(af6, ip6af_list);
+				frag6_nfrags--;
+				q6->ip6q_nfrag--;
 				pool_put(&ip6af_pool, af6);
 
 				/* adjust pointer. */
```