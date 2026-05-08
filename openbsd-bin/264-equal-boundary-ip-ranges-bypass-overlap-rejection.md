# Equal-Boundary IP Ranges Bypass Overlap Rejection

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`usr.sbin/rpki-client/ip.c:159`

## Summary

`rpki-client` incorrectly treats equal inclusive IP range boundaries as non-overlapping while parsing RFC 3779 `IPAddrBlocks`.

Because IP address ranges are inclusive, two entries sharing an endpoint overlap. The previous logic used `<=` and `>=` in the disjoint-range test, allowing certificates with adjacent-by-equality or duplicate singleton resources to pass overlap rejection.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced against the supplied `usr.sbin/rpki-client/ip.c` source and patched by tightening the range-disjoint comparisons.

## Preconditions

A certificate contains multiple `IPAddressOrRange` entries for the same AFI.

## Proof

`sbgp_parse_ipaddrblocks()` parses attacker-supplied `IPAddrBlocks` and appends every parsed entry through `append_ip()`.

`append_ip()` relies on `ip_addr_check_overlap()` as the RFC 3779 overlap rejection control.

The vulnerable overlap logic was:

```c
if (memcmp(ips[i].max, ip->min, sz) <= 0 ||
    memcmp(ips[i].min, ip->max, sz) >= 0)
        continue;
```

For inclusive ranges, equality is overlap. A previous IPv4 range:

```text
[10.0.0.0, 10.0.0.255]
```

followed by:

```text
[10.0.0.255, 10.0.1.0]
```

shares `10.0.0.255`.

However, `memcmp(ips[i].max, ip->min, 4) == 0`, so the old code entered `continue` and accepted the new overlapping entry. The same failure mode applies to duplicate singleton `/32` entries.

No later validation was identified that rejects the accepted overlap; `valid_cert()` checks resource coverage, not pairwise overlap.

## Why This Is A Real Bug

RFC 3779 IP resources are inclusive ranges. Equality at either boundary means the two resources share at least one IP address.

The old logic classified equality as disjoint, so malformed certificates with overlapping `IPAddressOrRange` entries could be accepted. This is a parser fail-open in a security control intended to reject invalid RPKI certificate resources.

## Fix Requirement

Use strict `<` and `>` comparisons when determining whether two inclusive ranges are disjoint.

Only these cases are disjoint:

```text
existing.max < new.min
existing.min > new.max
```

Equality must fall through to the overlap rejection path.

## Patch Rationale

The patch changes only the disjoint-range predicates in `ip_addr_check_overlap()`:

```diff
- if (memcmp(ips[i].max, ip->min, sz) <= 0 ||
-     memcmp(ips[i].min, ip->max, sz) >= 0)
+ if (memcmp(ips[i].max, ip->min, sz) < 0 ||
+     memcmp(ips[i].min, ip->max, sz) > 0)
        continue;
```

This preserves valid non-overlapping ranges while ensuring equal-boundary ranges and duplicate singleton entries are rejected as overlaps.

## Residual Risk

None

## Patch

`264-equal-boundary-ip-ranges-bypass-overlap-rejection.patch`

```diff
diff --git a/usr.sbin/rpki-client/ip.c b/usr.sbin/rpki-client/ip.c
index d04f626..90b9fbe 100644
--- a/usr.sbin/rpki-client/ip.c
+++ b/usr.sbin/rpki-client/ip.c
@@ -150,8 +150,8 @@ ip_addr_check_overlap(const struct cert_ip *ip, const char *fn,
 	for (i = 0; i < num_ips; i++) {
 		if (ips[i].afi != ip->afi)
 			continue;
-		if (memcmp(ips[i].max, ip->min, sz) <= 0 ||
-		    memcmp(ips[i].min, ip->max, sz) >= 0)
+		if (memcmp(ips[i].max, ip->min, sz) < 0 ||
+		    memcmp(ips[i].min, ip->max, sz) > 0)
 			continue;
 		if (!quiet) {
 			warnx("%s: RFC 3779 section 2.2.3.5: "
```