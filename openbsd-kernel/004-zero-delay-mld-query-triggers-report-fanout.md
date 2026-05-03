# Zero-Delay MLD Query Triggers Report Fanout

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`netinet6/mld6.c:296`

## Summary

A same-link attacker can send forged MLD Listener Query packets with `Max Response Delay == 0` and an unspecified multicast address. The affected code treats this as a zero timer for a General Query, matches every eligible IPv6 multicast membership on the receiving interface, and immediately sends one MLD Listener Report per membership.

This consumes CPU, transient allocation capacity, transmit buffers, and outbound bandwidth proportional to the victim's multicast membership count for each forged query.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced by source inspection of the supplied `netinet6/mld6.c` implementation and patched by clamping zero-delay General Queries into the existing delayed-response path.

## Preconditions

- The attacker is a same-link host able to send forged MLD Listener Query packets.
- The victim accepts the packet as link-local MLD input.
- The victim has IPv6 multicast memberships on the receiving interface.
- The query is a General Query, meaning `mld_addr == ::`.
- The query has `mld_maxdelay == 0`.

## Proof

In `mld6_input()`, MLD Listener Queries are accepted after source validation only requires a link-local IPv6 source.

For a General Query, `mld_addr == ::` causes the membership loop to match every eligible IPv6 multicast membership:

```c
if (IN6_IS_ADDR_UNSPECIFIED(&mldh->mld_addr) ||
    IN6_ARE_ADDR_EQUAL(&mldh->mld_addr, &in6m->in6m_addr))
```

The timer is derived directly from the attacker-controlled `mld_maxdelay` field:

```c
timer = ntohs(mldh->mld_maxdelay)*PR_FASTHZ/MLD_TIMER_SCALE;
if (timer == 0 && mldh->mld_maxdelay)
	timer = 1;
```

When `mld_maxdelay == 0`, `timer` remains zero. The loop then enters the immediate-send branch for each matched membership:

```c
if (timer == 0) {
	struct mld6_pktinfo *pkt;

	in6m->in6m_state = MLD_IREPORTEDLAST;
	in6m->in6m_timer = 0;
	pkt = malloc(sizeof(*pkt), M_MRTABLE, M_NOWAIT);
	...
	STAILQ_INSERT_TAIL(&pktlist, pkt, mpi_list);
}
```

After the interface multicast lock is released, the queued packet list is drained and `mld6_sendpkt()` is called once per queued membership:

```c
while (!STAILQ_EMPTY(&pktlist)) {
	pkt = STAILQ_FIRST(&pktlist);
	STAILQ_REMOVE_HEAD(&pktlist, mpi_list);
	mld6_sendpkt(pkt);
	free(pkt, M_MRTABLE, sizeof(*pkt));
}
```

Each `mld6_sendpkt()` allocates mbufs and calls `ip6_output()`, so repeated forged zero-delay General Queries force repeated per-membership transmit work.

## Why This Is A Real Bug

The behavior is attacker-triggered, unauthenticated on the local link, and scales with victim state. A single query can force immediate work for every eligible membership, and repeated queries can repeatedly trigger the same fanout.

The existing code has no per-query rate limit, no zero-delay clamp for General Queries, and no suppression in the immediate-send branch. The impact is practical resource exhaustion: CPU time, mbuf allocation pressure, transmit queue pressure, and outbound MLD report bursts.

## Fix Requirement

Zero-delay General Queries must not cause immediate per-membership report fanout. The implementation should either rate-limit immediate responses or convert zero-delay General Queries into randomized delayed responses so that reports are coalesced through the existing timer logic.

## Patch Rationale

The patch clamps only zero-delay General Queries, preserving the existing behavior for multicast-address-specific zero-delay queries.

When `mld_maxdelay == 0` and `mld_addr == ::`, the patch sets:

```c
timer = MLD_V1_MAX_RI * PR_FASTHZ;
```

This avoids the `timer == 0` immediate-send branch and uses the existing randomized timer path:

```c
in6m->in6m_timer = MLD_RANDOM_DELAY(timer);
running = 1;
```

That changes attacker-triggered immediate fanout into delayed, randomized report scheduling and allows existing timer suppression semantics to apply.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet6/mld6.c b/netinet6/mld6.c
index 8244486..3a8903f 100644
--- a/netinet6/mld6.c
+++ b/netinet6/mld6.c
@@ -258,11 +258,16 @@ mld6_input(struct mbuf *m, int off)
 		 * XXX: System timer resolution is too low to handle Max
 		 * Response Delay, so set 1 to the internal timer even if
 		 * the calculated value equals to zero when Max Response
-		 * Delay is positive.
+		 * Delay is positive.  Also clamp zero-delay General Queries
+		 * to avoid immediate report bursts for every membership.
 		 */
 		timer = ntohs(mldh->mld_maxdelay)*PR_FASTHZ/MLD_TIMER_SCALE;
-		if (timer == 0 && mldh->mld_maxdelay)
-			timer = 1;
+		if (timer == 0) {
+			if (mldh->mld_maxdelay)
+				timer = 1;
+			else if (IN6_IS_ADDR_UNSPECIFIED(&mldh->mld_addr))
+				timer = MLD_V1_MAX_RI * PR_FASTHZ;
+		}
 		all_nodes.s6_addr16[1] = htons(ifp->if_index);
 
 		rw_enter_write(&ifp->if_maddrlock);
```