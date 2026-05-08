# IPv6 host authorization compares only 32 bits

## Classification

Authorization bypass, high severity, certain confidence.

## Affected Locations

`usr.sbin/lpd/engine_lpr.c:357`

## Summary

`lpd` host authorization truncates IPv6 address comparisons to 32 bits. In `cmpsockaddr()`, the `AF_INET6` branch compares `sin6_addr` buffers but uses the IPv4 address length, so only the first 4 bytes of a 16-byte IPv6 address are checked. A remote IPv6 client whose source address shares the first 32 bits with an allowed `hosts.lpd` IPv6 entry can be accepted as that host.

## Provenance

Verified from the provided affected source, reproduced finding summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`hosts.lpd` allows an IPv6 host or a hostname resolving to an IPv6 address.

## Proof

`lpr_allowedhost()` authorizes remote clients by:

- resolving the client address to a hostname,
- checking a reverse/forward DNS roundtrip with `matchaddr(host, sa, &e)`,
- scanning `hosts.lpd`,
- calling `matchaddr()` for each allow or deny entry,
- accepting the client when `ok > 0`.

`matchaddr()` resolves a hostname and accepts when `cmpsockaddr(sa, r->ai_addr) == 0`.

In the vulnerable `AF_INET6` case:

```c
aa = &(((const struct sockaddr_in6*)a)->sin6_addr);
ab = &(((const struct sockaddr_in6*)b)->sin6_addr);
l = sizeof(((const struct sockaddr_in*)a)->sin_addr);
return memcmp(aa, ab, l);
```

`aa` and `ab` point to 16-byte IPv6 addresses, but `l` is `sizeof(struct in_addr)`, i.e. 4 bytes. Therefore, any IPv6 address sharing the first 32 bits with the allowed resolved address compares equal.

When this partial comparison succeeds, `lpr_allowedhost_res()` is called with `reject == NULL`, and the frontend proceeds with remote LPR operations including receiving jobs, displaying queues, and removing jobs.

## Why This Is A Real Bug

The code intends to compare complete socket addresses of the same address family. The IPv4 branch correctly compares an IPv4 address length. The IPv6 branch selects IPv6 address fields but mistakenly reuses the IPv4 address size. This creates a concrete authorization bypass because equality is used directly to decide whether a remote host matches an allowed `hosts.lpd` entry.

The reproduced flow confirms that the truncated comparison affects both the DNS roundtrip check and `hosts.lpd` authorization matching.

## Fix Requirement

Use the full IPv6 address size when comparing `AF_INET6` addresses:

```c
sizeof(((const struct sockaddr_in6 *)a)->sin6_addr)
```

## Patch Rationale

The patch changes only the comparison length in the `AF_INET6` branch. It preserves the existing authorization flow and `memcmp()` behavior while making IPv6 equality require all 128 bits to match, as intended.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/lpd/engine_lpr.c b/usr.sbin/lpd/engine_lpr.c
index 2d019d8..f1d4cd8 100644
--- a/usr.sbin/lpd/engine_lpr.c
+++ b/usr.sbin/lpd/engine_lpr.c
@@ -355,7 +355,7 @@ cmpsockaddr(const struct sockaddr *a, const struct sockaddr *b)
 	case AF_INET6:
 		aa = &(((const struct sockaddr_in6*)a)->sin6_addr);
 		ab = &(((const struct sockaddr_in6*)b)->sin6_addr);
-		l = sizeof(((const struct sockaddr_in*)a)->sin_addr);
+		l = sizeof(((const struct sockaddr_in6*)a)->sin6_addr);
 		return memcmp(aa, ab, l);
 
 	}
```