# Oversized RIPng Request Overreads Reply Buffer

## Classification

High severity information disclosure.

Confidence: certain.

## Affected Locations

`usr.sbin/route6d/route6d.c:1368`

## Summary

`route6d` accepts RIPng request datagrams into a stack buffer, derives the request entry count from the received datagram length, and passes that count to `riprequest()` without constraining it to the global transmit buffer size. For specific RIPng requests, `riprequest()` replies with `sendpacket(sin6, RIPSIZE(nn))`. `sendpacket()` always transmits from global `ripbuf`, so an oversized `nn` makes `sendmsg()` copy past the `ripbuf` allocation and return adjacent process memory to the requester.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can send RIPng request datagrams to `route6d` on UDP port 521 over IPv6.

## Proof

`riprecv()` reads an attacker-controlled datagram into local `buf[4 * RIP6_MAXMTU]`, computes:

```c
nn = (len - sizeof(struct rip6) + sizeof(struct netinfo6)) /
    sizeof(struct netinfo6);
```

It then dispatches RIPng requests before response-only source and hop-limit checks:

```c
if (rp->rip6_cmd == RIP6_REQUEST) {
    ...
    riprequest(ifcp, np, nn, &fsock);
    ...
}
```

For any request other than the one-entry whole-table request, `riprequest()` processes `nn` received entries and replies with:

```c
(void)sendpacket(sin6, RIPSIZE(nn));
```

`sendpacket()` does not send from the received request buffer. It always sends from global `ripbuf` and trusts the supplied length:

```c
iov[0].iov_base = (caddr_t)ripbuf;
iov[0].iov_len = len;
...
sendmsg(ripsock, &m, 0)
```

`ripbuf` is allocated as:

```c
ripbuf = calloc(RIP6_MAXMTU, 1)
```

With the committed structure layout, `RIPSIZE(75)` is already approximately 1504 bytes, exceeding the 1500-byte `ripbuf` allocation. Larger requests can therefore make `sendmsg()` overread thousands of bytes after `ripbuf` and disclose them in the UDP response.

## Why This Is A Real Bug

The attacker controls the received RIPng request length and therefore controls `nn`. The vulnerable request path is reachable before the stricter response validation checks. The outbound copy source is the fixed-size heap allocation `ripbuf`, while the outbound copy length is derived from the unbounded request entry count. This creates a direct, remotely triggerable heap overread with network-visible disclosure.

## Fix Requirement

Before using `nn` to construct a response length, cap it so `RIPSIZE(nn) <= RIP6_MAXMTU`, or build specific replies into `ripbuf` with explicit bounds checking.

## Patch Rationale

The patch bounds `nn` in `riprequest()` before the specific-request response loop and before `sendpacket()` receives the computed response size:

```diff
+       if (RIPSIZE(nn) > RIP6_MAXMTU)
+           nn = (RIP6_MAXMTU - sizeof(struct rip6) +
+               sizeof(struct netinfo6)) / sizeof(struct netinfo6);
```

This preserves existing specific-request behavior for valid-size requests and prevents `sendpacket()` from being called with a length larger than the allocated `ripbuf`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/route6d/route6d.c b/usr.sbin/route6d/route6d.c
index 5a49e8c..22163cc 100644
--- a/usr.sbin/route6d/route6d.c
+++ b/usr.sbin/route6d/route6d.c
@@ -1331,6 +1331,9 @@ riprequest(struct ifc *ifcp, struct netinfo6 *np, int nn,
 	if (!(nn == 1 && IN6_IS_ADDR_UNSPECIFIED(&np->rip6_dest) &&
 	      np->rip6_plen == 0 && np->rip6_metric == HOPCNT_INFINITY6)) {
 		/* Specific response, don't split-horizon */
+		if (RIPSIZE(nn) > RIP6_MAXMTU)
+			nn = (RIP6_MAXMTU - sizeof(struct rip6) +
+			    sizeof(struct netinfo6)) / sizeof(struct netinfo6);
 		log_debug("\tRIP Request");
 		for (i = 0; i < nn; i++, np++) {
 			rrt = rtsearch(np, NULL);
```