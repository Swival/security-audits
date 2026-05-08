# Invalid IA_PREFIX Length Terminates Engine

## Classification

Denial of service, high severity, confidence certain.

## Affected Locations

`sbin/dhcp6leased/engine.c:850`

## Summary

A DHCPv6 packet containing an `IA_PREFIX` option with `prefix_len > 128` causes `dhcp6leased`'s engine process to terminate. The value is attacker-controlled from the local network and is passed unchecked into `in6_prefixlen2mask()`, which calls `fatalx()` for invalid IPv6 prefix lengths.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client accepts DHCPv6 packets from the local network.
- The interface is configured for prefix delegation.
- The attacker can act as, or inject packets from, a DHCPv6 server or peer on the local network.

## Proof

The reproduced fault path is deterministic:

- `engine_dispatch_frontend()` accepts `IMSG_DHCP`, copies the packet data, and calls `parse_dhcp()` for the interface.
- `parse_dhcp()` handles `DHO_IA_PD` and calls `parse_ia_pd_options()` when `ntohl(iapd.iaid) < iface_conf->ia_count`.
- `parse_ia_pd_options()` handles `DHO_IA_PREFIX`, copies the attacker-supplied `struct dhcp_iaprefix`, and assigns `iaprefix.prefix_len` directly to `prefix->prefix_len`.
- The same function then calls `in6_prefixlen2mask(&mask, prefix->prefix_len)`.
- `in6_prefixlen2mask()` calls `fatalx()` when `len > 128`.
- Therefore, an `IA_PREFIX` with `prefix_len` in `129..255`, nonzero `vltime`, and `vltime >= pltime` exits the engine before later DHCP message or state validation.

## Why This Is A Real Bug

IPv6 prefix lengths are valid only in the range `0..128`. The packet parser accepts an 8-bit network-supplied `prefix_len` and uses it before validating the range. The downstream helper treats out-of-range input as a fatal programming error rather than malformed network input, so a malformed DHCPv6 packet becomes a process-killing condition.

This is externally triggerable from the local network under normal DHCPv6 threat assumptions and stops DHCPv6 lease handling.

## Fix Requirement

Reject `IA_PREFIX` options with `prefix_len > 128` before assigning the value to stored prefix state or passing it to `in6_prefixlen2mask()`.

## Patch Rationale

The patch adds an explicit bounds check in `parse_ia_pd_options()` immediately after validating lifetimes and before copying `iaprefix.prefix_len` into `prefix->prefix_len`. Invalid delegated prefixes are treated like other malformed or unusable IA_PD contents: a warning is logged and the IA_PD is ignored without terminating the engine.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/dhcp6leased/engine.c b/sbin/dhcp6leased/engine.c
index b818b32..1f2202c 100644
--- a/sbin/dhcp6leased/engine.c
+++ b/sbin/dhcp6leased/engine.c
@@ -1017,6 +1017,12 @@ parse_ia_pd_options(uint8_t *p, size_t len, struct prefix *prefix)
 				break;
 			}
 
+			if (iaprefix.prefix_len > 128) {
+				log_warnx("%s: invalid prefix length, ignoring IA_PD",
+				    __func__);
+				break;
+			}
+
 			prefix->prefix = iaprefix.prefix;
 			prefix->prefix_len = iaprefix.prefix_len;
 			prefix->vltime = ntohl(iaprefix.vltime);
```