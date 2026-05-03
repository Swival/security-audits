# IPv6 RH0 segleft underflows address index

## Classification

High severity out-of-bounds read in IPv6 AH output header processing.

Confidence: certain.

## Affected Locations

`netinet/ip_ah.c:461`

## Summary

`ah_massage_headers()` mishandles IPv6 Type 0 routing headers during AH output. When an attacker-controlled RH0 has `Segments Left == 0`, the code indexes `addr[rh0->ip6r0_segleft - 1]`, which underflows to `addr[-1]`. The following `memmove()` also derives its length from `(0 - 1)`, producing an invalid large copy length.

## Provenance

Reported and verified via Swival Security Scanner: https://swival.dev

## Preconditions

- AH output processes an attacker-controlled IPv6 packet containing RH0.
- The packet reaches `ah_output()` with `out=1`.
- The RH0 field `ip6r0_segleft` is zero.
- A bridged IPsec output path or equivalent path can feed the frame into AH output before universal RH0 rejection.

## Proof

In `ah_output()`, the packet is passed to:

`ah_massage_headers(&m, tdb->tdb_dst.sa.sa_family, skip, ahx->type, 1)`

For IPv6 routing headers, `ah_massage_headers()` casts Type 0 routing headers to `struct ip6_rthdr0`:

```c
rh0 = (struct ip6_rthdr0 *)rh;
addr = (struct in6_addr *)(rh0 + 1);

for (i = 0; i < rh0->ip6r0_segleft; i++)
	if (IN6_IS_SCOPE_EMBED(&addr[i]))
		addr[i].s6_addr16[1] = 0;

finaldst = addr[rh0->ip6r0_segleft - 1];
memmove(&addr[1], &addr[0],
    sizeof(struct in6_addr) *
    (rh0->ip6r0_segleft - 1));
```

With `ip6r0_segleft == 0`:

- The loop executes zero times.
- `finaldst = addr[0 - 1]` reads before the RH0 address array.
- The `memmove()` length is computed from `sizeof(struct in6_addr) * (0 - 1)`, yielding an invalid large size.

The reproduced path confirms reachability through AH output:

- Bridged IPsec output can pass attacker-controlled IPv6 frames into IPsec processing.
- `ipsp_process_packet()` reaches AH output.
- `ah_output()` calls `ah_massage_headers(..., out=1)`.
- RH0 with zero `Segments Left` triggers the underflowed access.

## Why This Is A Real Bug

The vulnerable index is directly derived from packet-controlled `ip6r0_segleft` without first validating that it is nonzero. C unsigned/integer arithmetic causes `rh0->ip6r0_segleft - 1` to become an invalid index when the field is zero.

This is not purely theoretical because reproduced analysis shows an AH output path can process attacker-controlled IPv6 traffic containing RH0. If `pf` runs and inspects the packet first, it may block RH0, but that is not universal; `pf_test()` returns immediately when `pf` is not running.

The likely practical impact is kernel out-of-bounds access and panic/DoS from a malicious L2 peer or bridged IPv6 sender whose packet matches outbound AH policy.

## Fix Requirement

Reject IPv6 RH0 headers with `ip6r0_segleft == 0` before using `ip6r0_segleft - 1` as an address-array index or `memmove()` length component.

## Patch Rationale

The patch adds a guard immediately after casting the routing header to `struct ip6_rthdr0` and before deriving `addr` or using `ip6r0_segleft`.

```c
rh0 = (struct ip6_rthdr0 *)rh;
if (rh0->ip6r0_segleft == 0)
	goto error6;
addr = (struct in6_addr *)(rh0 + 1);
```

This preserves existing error handling semantics by routing malformed IPv6 extension headers to `error6`, which frees temporary allocation when needed, increments AH header-drop statistics, returns `EINVAL`, and drops the packet.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/ip_ah.c b/netinet/ip_ah.c
index 9554aa9..b726623 100644
--- a/netinet/ip_ah.c
+++ b/netinet/ip_ah.c
@@ -457,6 +457,8 @@ ah_massage_headers(struct mbuf **mp, int af, int skip, int alg, int out)
 					int i;
 
 					rh0 = (struct ip6_rthdr0 *)rh;
+					if (rh0->ip6r0_segleft == 0)
+						goto error6;
 					addr = (struct in6_addr *)(rh0 + 1);
 
 					for (i = 0; i < rh0->ip6r0_segleft; i++)
```