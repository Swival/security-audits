# SOII RA Prefix Length Kills slaacd

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`sbin/slaacd/engine.c:1096`

## Summary

A local-link IPv6 peer can send a Router Advertisement containing an autonomous Prefix Information option with `prefix_len > 128`. When SOII and autoconf are enabled on an up interface, `slaacd` accepts the invalid length, reaches address generation, passes the attacker-controlled value to `in6_prefixlen2mask`, and terminates through `fatalx`, stopping IPv6 autoconfiguration.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- SOII enabled on the target interface.
- Autoconf enabled on the target interface.
- Interface is up and not in `IF_DOWN`.
- Attacker is a local-link IPv6 peer able to send Router Advertisements.

## Proof

`engine_dispatch_frontend` accepts `IMSG_RA` and calls `parse_ra` for known non-down interfaces.

In `parse_ra`, Prefix Information options with `nd_opt_len == 4` are parsed, and `nd_opt_pi_prefix_len` is copied directly into `prefix->prefix_len` without an upper-bound check.

`update_iface_ra` filters prefixes for autonomous mode, nonzero valid lifetime, preferred lifetime not exceeding valid lifetime, and non-link-local prefix, but does not reject `prefix_len > 128`.

`update_iface_ra_prefix` can generate a new non-temporary address when:

```c
!found && iface->autoconf && (iface->soii || prefix->prefix_len <= 64)
```

With `iface->soii` true, this bypasses the `prefix_len <= 64` guard.

`gen_address_proposal` copies `prefix->prefix_len` into `addr_proposal->prefix_len`, then calls `gen_addr`.

`gen_addr` calls:

```c
in6_prefixlen2mask(&addr_proposal->mask, addr_proposal->prefix_len);
```

`in6_prefixlen2mask` treats `len > 128` as fatal:

```c
if (0 > len || len > 128)
	fatalx("%s: invalid prefix length(%d)\n", __func__, len);
```

A concrete reproducing packet is a Router Advertisement from a link-local source with hop limit 255, containing an autonomous Prefix Information option of length 4, a non-link-local prefix, `vltime > 0`, `pltime <= vltime`, and `prefix_len = 129`. On a managed up interface before an existing non-temporary proposal is found, this deterministically kills the `slaacd` engine.

## Why This Is A Real Bug

The attacker-controlled RA field reaches a fatal process exit without validation. `prefix_len > 128` is invalid for IPv6 masks, but malformed network input should be rejected during RA parsing, not allowed to terminate the autoconfiguration engine. The impact is loss of SLAAC processing for the affected daemon, matching denial of service.

## Fix Requirement

Reject Router Advertisement Prefix Information options whose `nd_opt_pi_prefix_len` is greater than 128 before storing the prefix or generating any address proposal.

## Patch Rationale

The patch validates `nd_opt_pi_prefix_len` immediately after confirming the Prefix Information option has the required length and before allocating or inserting a `radv_prefix`. Invalid options now follow the existing RA parse error path via `goto err`, freeing the partially built RA and preventing the invalid length from reaching `gen_addr` or `in6_prefixlen2mask`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/slaacd/engine.c b/sbin/slaacd/engine.c
index f2320c0..f8946bd 100644
--- a/sbin/slaacd/engine.c
+++ b/sbin/slaacd/engine.c
@@ -1493,10 +1493,16 @@ parse_ra(struct slaacd_iface *iface, struct imsg_ra *ra)
 				goto err;
 			}
 
+			prf = (struct nd_opt_prefix_info*) nd_opt_hdr;
+			if (prf->nd_opt_pi_prefix_len > 128) {
+				log_warnx("invalid ND_OPT_PREFIX_INFORMATION: "
+				    "prefix length > 128");
+				goto err;
+			}
+
 			if ((prefix = calloc(1, sizeof(*prefix))) == NULL)
 				fatal("calloc");
 
-			prf = (struct nd_opt_prefix_info*) nd_opt_hdr;
 			prefix->prefix = prf->nd_opt_pi_prefix;
 			prefix->prefix_len = prf->nd_opt_pi_prefix_len;
 			prefix->onlink = prf->nd_opt_pi_flags_reserved &
```