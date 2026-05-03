# Source-Route Tag Deletion Uses Payload Pointer

## Classification

Memory corruption, high severity, certain confidence.

## Affected Locations

`netinet/ip_input.c:1516`

## Summary

`ip_srcroute()` deletes an mbuf tag using a pointer to the tag payload instead of the original `struct m_tag` header. When a source-routed IPv4 packet creates a `PACKET_TAG_SRCROUTE` tag and a later reply path calls `ip_srcroute()`, `m_tag_delete()` receives an invalid list element pointer, corrupting mbuf tag list handling or causing a kernel panic.

## Provenance

Verified and reproduced from scanner output attributed to Swival Security Scanner: https://swival.dev

## Preconditions

IPv4 source routing is enabled and `ip_srcroute()` is invoked on a packet carrying a saved source-route tag.

## Proof

`ip_dooptions()` handles LSRR/SSRR options. At the end of a source route, it calls `save_rte()`, which allocates a `PACKET_TAG_SRCROUTE` mbuf tag and stores the route data in the payload immediately after the tag header:

```c
mtag = m_tag_get(PACKET_TAG_SRCROUTE, sizeof(*isr), M_NOWAIT);
isr = (struct ip_srcrt *)(mtag + 1);
m_tag_prepend(m, mtag);
```

Later, `ip_srcroute()` finds the real tag header:

```c
mtag = m_tag_find(m0, PACKET_TAG_SRCROUTE, NULL);
isr = (struct ip_srcrt *)(mtag + 1);
```

After constructing the return route, the vulnerable code deletes the tag using the payload pointer:

```c
m_tag_delete(m0, (struct m_tag *)isr);
```

The reproduced path confirms reachability through a source-routed TCP SYN to a listening IPv4 socket. The packet reaches `syn_cache_add`, which calls `ip_srcroute(m)` at `netinet/tcp_input.c:3831`.

`m_tag_delete()` expects the actual `struct m_tag *` and performs list removal with `SLIST_REMOVE` at `kern/uipc_mbuf2.c:292`. `SLIST_REMOVE` walks list links looking for the exact list member at `sys/queue.h:150`. A payload pointer is not a valid tag-list member, so removal operates on a non-tag address and can lead to NULL dereference, list corruption, or `pool_put` on the wrong address.

## Why This Is A Real Bug

The code already preserves the correct tag header pointer in `mtag`. The payload pointer `isr` is derived from `mtag + 1` and is intentionally not a `struct m_tag`. Passing `isr` to `m_tag_delete()` violates the mbuf tag API contract and causes list manipulation on an address that was never inserted into the tag list.

The trigger is remote and unauthenticated under the stated configuration: an IPv4 sender can provide LSRR/SSRR options that cause `save_rte()` to attach the source-route tag, and normal TCP reply setup can later call `ip_srcroute()`.

## Fix Requirement

Call `m_tag_delete()` with the original `struct m_tag *mtag`, not the derived `struct ip_srcrt *isr` payload pointer.

## Patch Rationale

The patch preserves existing behavior while correcting the pointer passed to the mbuf tag deletion API. `mtag` is the value returned by `m_tag_find()` and is the list element inserted earlier by `m_tag_prepend()`. `isr` remains valid only as the payload used to build the return-route options.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/ip_input.c b/netinet/ip_input.c
index 099aadb..047c668 100644
--- a/netinet/ip_input.c
+++ b/netinet/ip_input.c
@@ -1510,9 +1510,9 @@ ip_srcroute(struct mbuf *m0)
 		*q++ = *p--;
 	}
 	/*
 	 * Last hop goes to final destination.
 	 */
 	*q = isr->isr_dst;
-	m_tag_delete(m0, (struct m_tag *)isr);
+	m_tag_delete(m0, mtag);
 	return (m);
 }
```