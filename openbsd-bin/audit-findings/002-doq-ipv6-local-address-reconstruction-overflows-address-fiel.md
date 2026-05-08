# DoQ IPv6 Local Address Reconstruction Overflows Address Field

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/unwind/libunbound/services/listen_dnsport.c:2764`

Patch location: `sbin/unwind/libunbound/services/listen_dnsport.c:3776`

## Summary

The IPv6 DoQ reply path reconstructs a local socket address from compact packet-info storage. It sets `*localaddrlen` to `sizeof(struct sockaddr_in6)` and then uses that full length when copying into `sa6->sin6_addr`, which is only a `struct in6_addr` field. This causes an out-of-bounds write past the IPv6 address field and reads past the stored `ipi6_addr`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- DoQ is enabled.
- IPv6 packet info support is available.
- A remote IPv6 DNS-over-QUIC client sends a query that is queued and answered later.

## Proof

`doq_conn_key_store_repinfo()` stores the DoQ connection key into `comm_reply`. For IPv6, `doq_repinfo_store_localaddr()` copies only `sizeof(struct in6_addr)` from `sa6->sin6_addr` into `repinfo->pktinfo.v6info.ipi6_addr` and marks `repinfo->srctype = 6`.

During reply handling, `doq_conn_key_from_repinfo()` calls `doq_repinfo_retrieve_localaddr()`. In the IPv6 branch, the function:

```c
*localaddrlen = (socklen_t)sizeof(struct sockaddr_in6);
memset(sa6, 0, *localaddrlen);
sa6->sin6_family = AF_INET6;
memmove(&sa6->sin6_addr, &repinfo->pktinfo.v6info.ipi6_addr,
    *localaddrlen);
```

The destination `&sa6->sin6_addr` is a 16-byte `struct in6_addr`, but the copy length is `sizeof(struct sockaddr_in6)`. This writes beyond the address field and reads beyond `ipi6_addr`.

The reproduced flow reaches the vulnerable copy through delayed DoQ reply lookup:

- `mesh_state_add_reply()` copies the `comm_reply` at `sbin/unwind/libunbound/services/mesh.c:1949`.
- Later reply handling reaches `doq_socket_send_reply()` via `sbin/unwind/libunbound/util/netevent.c:6741`.
- `doq_conn_key_from_repinfo()` reconstructs a stack `struct doq_conn_key key` created at `sbin/unwind/libunbound/util/netevent.c:2806`.
- The overflow corrupts adjacent stack memory during DoQ connection lookup.

## Why This Is A Real Bug

The source object contains only an IPv6 address, and the destination field is only an IPv6 address. Using the full `struct sockaddr_in6` length is inconsistent with both storage and destination bounds.

The trigger is remotely reachable by an IPv6 DoQ client. Although the copied bytes are not DNS-payload-controlled, the operation is attacker-triggered and corrupts stack state used for DoQ reply connection lookup.

## Fix Requirement

Copy exactly `sizeof(struct in6_addr)` in the IPv6 reconstruction path and `sizeof(struct in_addr)` in the IPv4 `IP_PKTINFO` path, matching the stored packet-info field and the destination field size in each case.

## Patch Rationale

The patch changes both the IPv6 and IPv4 `IP_PKTINFO` `memmove()` lengths from `*localaddrlen` to the correct address-only size. The IPv4 `IP_RECVDSTADDR` path already uses `sizeof(struct in_addr)` and is unaffected.

`*localaddrlen` remains `sizeof(struct sockaddr_in6)` or `sizeof(struct sockaddr_in)` because it describes the reconstructed socket address object as a whole. It must not be reused as the byte count for copying the embedded address field.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/libunbound/services/listen_dnsport.c b/sbin/unwind/libunbound/services/listen_dnsport.c
index f7fcca1..683e38f 100644
--- a/sbin/unwind/libunbound/services/listen_dnsport.c
+++ b/sbin/unwind/libunbound/services/listen_dnsport.c
@@ -3776,13 +3776,13 @@ doq_repinfo_retrieve_localaddr(struct comm_reply* repinfo,
 		memset(sa6, 0, *localaddrlen);
 		sa6->sin6_family = AF_INET6;
 		memmove(&sa6->sin6_addr, &repinfo->pktinfo.v6info.ipi6_addr,
-			*localaddrlen);
+			sizeof(struct in6_addr));
 		sa6->sin6_port = repinfo->doq_srcport;
 #endif
 	} else {
 #ifdef IP_PKTINFO
 		struct sockaddr_in* sa = (struct sockaddr_in*)localaddr;
 		*localaddrlen = (socklen_t)sizeof(struct sockaddr_in);
 		memset(sa, 0, *localaddrlen);
 		sa->sin_family = AF_INET;
 		memmove(&sa->sin_addr, &repinfo->pktinfo.v4info.ipi_addr,
-			*localaddrlen);
+			sizeof(struct in_addr));
 		sa->sin_port = repinfo->doq_srcport;
 #elif defined(IP_RECVDSTADDR)
```