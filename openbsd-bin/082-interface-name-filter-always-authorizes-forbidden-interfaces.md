# Interface Name Filter Always Authorizes Forbidden Interfaces

## Classification

High severity security control failure.

## Affected Locations

`usr.sbin/npppd/npppd/privsep.c:1075`

## Summary

`privsep_npppd_check_ifname()` is intended to authorize only interface names beginning with `tun`, `pppac`, or `pppx`. Its non-match fallthrough returned success, so every interface name was accepted. A compromised jailed `npppd` child able to send imsgs to the privileged helper could request privileged interface operations on non-PPP interfaces.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can send imsgs to the `npppd` privileged helper, for example through compromise of the jailed `npppd` child that already communicates with the helper over the privsep socketpair.

## Proof

`privsep_priv_dispatch_imsg()` handles `PRIVSEP_SET_IF_ADDR` by reading the attacker-controlled `ifname` from `imsg.data`.

The dispatch path checks authorization before making the privileged ioctl:

- `PRIVSEP_SET_IF_ADDR` calls `privsep_npppd_check_set_if_addr(a)` at `usr.sbin/npppd/npppd/privsep.c:824`.
- `privsep_npppd_check_set_if_addr()` delegates to `privsep_npppd_check_ifname(arg->ifname)`.
- `privsep_npppd_check_ifname()` returns `0` for allowed prefixes `tun`, `pppac`, and `pppx`.
- The same function also returned `0` after no prefix matched.
- Because `0` means authorized in this code, forbidden names such as `em0` were accepted.
- Execution then reached `ioctl(s, SIOCAIFADDR, &ifra)` at `usr.sbin/npppd/npppd/privsep.c:847`.

The same broken helper is reused by get/set/delete address and get/set flags checks, so the authorization failure affects all interface-name-gated privileged operations.

## Why This Is A Real Bug

The privileged helper exists to constrain operations requested by less-privileged jailed code. The interface name filter is the specific security boundary intended to limit privileged network interface operations to `tun`, `pppac`, and `pppx` devices.

Returning success on the deny/fallthrough branch makes the filter fail open. A compromised jailed child can therefore induce the privileged helper to add, delete, query, or modify flags for forbidden interfaces, including non-PPP interfaces. This enables privileged network configuration integrity changes and denial of service.

## Fix Requirement

`privsep_npppd_check_ifname()` must return failure when the supplied interface name does not match an explicitly allowed prefix.

## Patch Rationale

The patch changes only the fallthrough return in `privsep_npppd_check_ifname()` from success to failure.

Allowed prefixes still return `0`, preserving existing behavior for `tun`, `pppac`, and `pppx`. Non-matching interface names now return `1`, causing callers such as `privsep_npppd_check_set_if_addr()` to reject the imsg with `EACCES` before privileged ioctls are reached.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/privsep.c b/usr.sbin/npppd/npppd/privsep.c
index e2304d9..4b15518 100644
--- a/usr.sbin/npppd/npppd/privsep.c
+++ b/usr.sbin/npppd/npppd/privsep.c
@@ -1081,7 +1081,7 @@ privsep_npppd_check_ifname(const char *ifname)
 	    startswith(ifname, "pppx"))
 		return (0);
 
-	return (0);
+	return (1);
 }
 
 static int
```