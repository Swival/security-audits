# Unauthenticated LLDP Frames Create Unbounded MSAP State

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/lldpd/lldpd.c:737`

## Summary

`lldpd` accepted unauthenticated LLDP frames from monitored Ethernet interfaces and created a new MSAP entry for every unique chassis ID and port ID pair with nonzero TTL. The receive path allocated a `struct lldp_msap`, inserted it into both per-interface and global lists, then allocated PDU storage sized to the received frame. There was no per-interface or global cap, so an adjacent sender could create unbounded live state until TTL expiry.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can send LLDP Ethernet frames on a monitored interface.

## Proof

The receive path parses LLDP frames in `ensock_recv`.

For a valid frame, the MSAP identifier length is derived from the first two TLVs after chassis ID, port ID, and TTL validation. Existing entries are searched by comparing `msap_pdu` against the incoming PDU prefix.

If no existing MSAP matches and TTL is nonzero, the original code:

- allocated a new `struct lldp_msap` at `usr.sbin/lldpd/lldpd.c:741`
- inserted it into the interface list at `usr.sbin/lldpd/lldpd.c:764`
- inserted it into the global daemon list at `usr.sbin/lldpd/lldpd.c:765`
- allocated or resized `msap_pdu` to the received PDU length at `usr.sbin/lldpd/lldpd.c:785`
- copied attacker-controlled PDU data at `usr.sbin/lldpd/lldpd.c:807`
- scheduled cleanup only by attacker-controlled TTL at `usr.sbin/lldpd/lldpd.c:815`

An adjacent LLDP sender can repeatedly send valid LLDP frames with unique chassis and port IDs and nonzero TTL values. Each unique identifier creates another live MSAP and PDU allocation. No per-interface or global limit existed before allocation.

## Why This Is A Real Bug

LLDP frames are unauthenticated at this layer, and the only attacker requirement is adjacency on a monitored interface. The attacker controls the uniqueness of chassis and port IDs and can keep TTL nonzero, causing persistent in-memory state. Although some allocation failures are handled, the daemon still permits unbounded growth up to memory pressure, producing denial of service through resource exhaustion or degraded operation.

## Fix Requirement

Before allocating a new MSAP for an unknown identifier, enforce both:

- a per-interface MSAP limit
- a global daemon MSAP limit

Frames that would exceed either limit must be rejected without allocating new MSAP or PDU state.

## Patch Rationale

The patch introduces fixed caps:

- `LLDPD_MAX_MSAPS` limits total daemon MSAP entries to 4096.
- `LLDPD_MAX_IF_MSAPS` limits MSAP entries per interface to 256.

During lookup, the patch counts existing entries on the receiving interface. Only when a frame would create a new MSAP does it count global entries and reject the frame if either cap is reached. Rejected frames increment `statsFramesDiscardedTotal` and return before `malloc(sizeof(*msap))`, preventing attacker-controlled unbounded state creation.

Existing MSAP updates are still allowed because the limit check runs only after lookup fails.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/lldpd/lldpd.c b/usr.sbin/lldpd/lldpd.c
index cbfa1d6..d45a731 100644
--- a/usr.sbin/lldpd/lldpd.c
+++ b/usr.sbin/lldpd/lldpd.c
@@ -63,6 +63,8 @@
 int rdaemon(int);
 
 #define LLDPD_USER		"_lldpd"
+#define LLDPD_MAX_MSAPS		4096
+#define LLDPD_MAX_IF_MSAPS	256
 
 #define CMSG_FOREACH(_cmsg, _msgp) \
 	for ((_cmsg) = CMSG_FIRSTHDR((_msgp)); \
@@ -594,6 +596,8 @@ ensock_recv(int s, short events, void *arg)
 	int ok;
 	unsigned int idlen;
 	unsigned int ttl;
+	unsigned int if_msaps = 0;
+	unsigned int msaps = 0;
 	struct timeval age;
 	int update = 0;
 
@@ -727,6 +731,7 @@ ensock_recv(int s, short events, void *arg)
 	}
 
 	TAILQ_FOREACH(msap, &ifp->if_msaps, msap_entry) {
+		if_msaps++;
 		if (msap->msap_id_len == idlen &&
 		    memcmp(msap->msap_pdu, buf, idlen) == 0)
 			break;
@@ -738,6 +743,17 @@ ensock_recv(int s, short events, void *arg)
 			return;
 		}
 
+		TAILQ_FOREACH(msap, &lldpd->msaps, msap_aentry)
+			msaps++;
+
+		if (if_msaps >= LLDPD_MAX_IF_MSAPS ||
+		    msaps >= LLDPD_MAX_MSAPS) {
+			ldebug("%s: too many msaps", ifp->if_key.if_name);
+			agent_counter_inc(lldpd, ifp,
+			    statsFramesDiscardedTotal);
+			return;
+		}
+
 		msap = malloc(sizeof(*msap));
 		if (msap == NULL) {
 			lwarn("%s: msap alloc", ifp->if_key.if_name);
```