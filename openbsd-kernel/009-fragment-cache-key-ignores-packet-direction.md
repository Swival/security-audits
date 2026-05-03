# fragment cache key ignores packet direction

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`net/pf_norm.c:157`

## Summary

`struct pf_frnode` stores `fn_direction`, and both IPv4 and IPv6 reassembly populate it from `dir`, but `pf_frnode_compare()` omits it from the RB tree key. As a result, fragment queues from opposite pf directions can alias when protocol, address family, source address, destination address, and fragment ID match. For IPv6, an attacker-controlled overlapping opposite-direction fragment can trigger the RFC 5722 discard path and flush a legitimate reassembly queue.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- pf IPv6 fragment reassembly is enabled.
- Matching IPv6 fragments traverse both pf directions.
- An attacker can send IPv6 fragments reusing another flow's source address, destination address, and fragment ID.

## Proof

`pf_reassemble6()` builds a fragment lookup key with:

- `key.fn_src.v6 = ip6->ip6_src`
- `key.fn_dst.v6 = ip6->ip6_dst`
- `key.fn_af = AF_INET6`
- `key.fn_proto = 0`
- `key.fn_direction = dir`

`pf_fillup_fragment()` then calls `pf_find_fragment(key, id)`. That lookup uses `RB_FIND(pf_frnode_tree, ...)`, which depends on `pf_frnode_compare()`.

Before the patch, `pf_frnode_compare()` compared only:

- `fn_proto`
- `fn_af`
- `fn_src`
- `fn_dst`

It did not compare `fn_direction`, so `RB_FIND()` could return a fragment node created for the opposite pf direction.

When the returned opposite-direction queue is IPv6 and the new fragment conflicts or overlaps, `pf_fillup_fragment()` reaches `free_ipv6_fragment`, then calls `pf_free_fragment(frag)`. `pf_free_fragment()` removes the queue and frees all queued fragment mbufs, discarding legitimate in-progress IPv6 reassembly state.

Reachability is practical because IPv6 fragments are passed into `pf_reassemble6()` by `pf_normalize_ip6()` when reassembly is enabled, and forwarded packets can be observed as `PF_OUT` while true inbound traffic remains `PF_IN`.

## Why This Is A Real Bug

The data model explicitly includes packet direction in `struct pf_frnode`, and reassembly code assigns it for both IPv4 and IPv6. Omitting it from the comparator makes distinct direction-specific keys indistinguishable in the RB tree. This violates the intended fragment-cache partitioning and enables cross-direction queue reuse.

For IPv6, overlapping fragments must discard the entire datagram queue. Therefore, a malicious peer can repeatedly inject matching opposite-direction fragments to flush legitimate fragmented IPv6 datagrams, causing denial of service for affected traffic.

## Fix Requirement

Include `fn_direction` in `pf_frnode_compare()` so fragment nodes are keyed by packet direction before address comparison.

## Patch Rationale

The patch adds `fn_direction` to the RB tree ordering after protocol and address family. This makes `PF_IN` and `PF_OUT` fragment nodes distinct even when source address, destination address, address family, protocol, and fragment ID match.

Placing the comparison before address comparison is consistent with the requested fix and avoids unnecessary address comparisons when direction already differs.

## Residual Risk

None

## Patch

```diff
diff --git a/net/pf_norm.c b/net/pf_norm.c
index 2ec8cb4..c3fa4c7 100644
--- a/net/pf_norm.c
+++ b/net/pf_norm.c
@@ -176,6 +176,8 @@ pf_frnode_compare(struct pf_frnode *a, struct pf_frnode *b)
 		return (diff);
 	if ((diff = a->fn_af - b->fn_af) != 0)
 		return (diff);
+	if ((diff = a->fn_direction - b->fn_direction) != 0)
+		return (diff);
 	if ((diff = pf_addr_compare(&a->fn_src, &b->fn_src, a->fn_af)) != 0)
 		return (diff);
 	if ((diff = pf_addr_compare(&a->fn_dst, &b->fn_dst, a->fn_af)) != 0)
```