# EVPN label length overflows VNI stack local

## Classification

Memory corruption; high severity; remotely triggerable by a malicious EVPN BGP peer under logging conditions.

## Affected Locations

`usr.sbin/bgpd/util.c:97`

## Summary

`log_evpnaddr()` copies `addr->labellen` bytes from an EVPN label stack into a 4-byte stack local `uint32_t vni`. EVPN type 2 parsing accepts either 3 or 6 trailing label bytes and stores that length in `prefix->labellen`. When a valid type 2 NLRI carries 6 trailing label bytes, update logging reaches `memcpy(&vni, addr->labelstack, addr->labellen)`, causing a 6-byte copy into a 4-byte object and corrupting two adjacent stack bytes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `bgpd` accepts EVPN routes from an attacker-controlled or malicious negotiated BGP peer.
- The peer sends an EVPN route type 2 NLRI with exactly 6 trailing label bytes.
- Accepted updates are logged, causing the parsed prefix to be formatted through `log_addr()` and `log_evpnaddr()`.

## Proof

The EVPN parser accepts type 2 NLRIs whose remaining VNI bytes are exactly 3 or 6:

- `nlri_get_evpn()` parses `EVPN_ROUTE_TYPE_2`.
- It checks that the remaining `evpnbuf` size is either 3 or 6.
- It assigns that size to `prefix->labellen`.
- It copies that many bytes into `prefix->labelstack`.

The logging path then formats the accepted prefix:

- `rde_update_update()` receives the update.
- With update logging enabled, `rde_update_log()` calls `log_addr(prefix)`.
- `log_addr()` dispatches `AID_EVPN` to `log_evpnaddr()`.

For EVPN route type 2, `log_evpnaddr()` declares a 4-byte local:

```c
uint32_t vni;
```

and previously copied attacker-controlled length bytes into it:

```c
memcpy(&vni, addr->labelstack, addr->labellen);
```

With `addr->labellen == 6`, this writes six bytes into a four-byte stack object, producing a two-byte stack overwrite during route logging.

## Why This Is A Real Bug

The vulnerable copy length is not hypothetical or unreachable. Committed parser logic explicitly accepts a 6-byte trailing label/VNI field for EVPN type 2 and records that value in `labellen`. The later logging code trusts `labellen` as the destination copy size even though the destination is fixed at `sizeof(uint32_t)`. This is a concrete stack buffer overflow reachable from accepted attacker-controlled BGP EVPN input when logging is enabled.

## Fix Requirement

The copy into `vni` must be bounded to the actual VNI width used by the formatter. For EVPN type 2, only the three VNI bytes should be copied, or values larger than `sizeof(vni)` must be rejected before copying.

## Patch Rationale

The patch changes the EVPN type 2 logging copy from using attacker-influenced `addr->labellen` to a fixed 3-byte VNI copy:

```diff
-		memcpy(&vni, addr->labelstack, addr->labellen);
+		memcpy(&vni, addr->labelstack, 3);
```

This matches the subsequent formatting operation, which derives the displayed VNI from the three-byte value using `htonl(vni) >> 8`. It also preserves acceptance of existing 6-byte type 2 NLRIs while ensuring the stack destination is not overrun during logging.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgpd/util.c b/usr.sbin/bgpd/util.c
index 6f8e6e6..8c447dc 100644
--- a/usr.sbin/bgpd/util.c
+++ b/usr.sbin/bgpd/util.c
@@ -95,7 +95,7 @@ log_evpnaddr(const struct bgpd_addr *addr, struct sockaddr *sa,
 
 	switch (addr->evpn.type) {
 	case EVPN_ROUTE_TYPE_2:
-		memcpy(&vni, addr->labelstack, addr->labellen);
+		memcpy(&vni, addr->labelstack, 3);
 		snprintf(buf, sizeof(buf), "[2]:[%s]:[%s]:[%d]:[48]:[%s]",
 		    log_rd(addr->rd), log_esi(addr->evpn.esi), htonl(vni) >> 8,
 		    log_mac(addr->evpn.mac));
```