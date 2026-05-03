# default rdomain bypasses SO_RTABLE privilege check

## Classification

authorization bypass; severity medium; confidence certain

## Affected Locations

`netinet6/ip6_output.c:1191`

## Summary

`ip6_ctloutput()` allowed an unprivileged process in the default routing domain to set `SO_RTABLE` to another existing routing table on an IPv6 socket without passing `suser()`. Subsequent IPv6 traffic from that socket used the selected routing table, bypassing the intended privilege gate for crossing routing namespaces.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Process starts in default rdomain / routing table `0`.
- Process can open an IPv6 socket.
- Target routing table exists.
- `SO_RTABLE` is set before socket state prevents `in_pcbset_rtableid()` from changing the PCB table.

## Proof

In `ip6_ctloutput()` handling `PRCO_SETOPT` / `SO_RTABLE`, the caller-controlled `rtid` is copied from the mbuf and compared with the process routing table:

```c
rtid = *mtod(m, u_int *);
if (inp->inp_rtableid == rtid)
	break;
/* needs privileges to switch when already set */
if (rtableid != rtid && rtableid != 0 &&
    (error = suser(p)) != 0)
	break;
error = in_pcbset_rtableid(inp, rtid);
```

For a process whose `p->p_p->ps_rtableid` is `0`, the condition `rtableid != rtid && rtableid != 0` is false for any requested non-zero `rtid`. Therefore `suser(p)` is skipped.

`in_pcbset_rtableid()` then accepts the change when the target table exists and the PCB is still eligible, assigning the requested routing table to the socket PCB. Outbound IPv6 paths propagate that PCB routing table into `m->m_pkthdr.ph_rtableid`, and `ip6_output()` routes using `in6_selectroute(..., m->m_pkthdr.ph_rtableid)`. UDP and TCP outputs both propagate the PCB table before route selection, so packets are sent through the chosen routing namespace.

## Why This Is A Real Bug

The existing check intended to require privilege when a socket switches away from the process routing table. The extra `rtableid != 0` term exempted the default rdomain from that rule, allowing unprivileged local processes in rdomain `0` to select other routing tables.

This is security-relevant because routing tables represent distinct routing namespaces. Allowing an unprivileged process to send IPv6 traffic through another namespace violates the authorization boundary enforced by `SO_RTABLE` privilege checks.

## Fix Requirement

Require `suser(p)` whenever the requested `SO_RTABLE` value differs from the process routing table, except when the socket is already set to that table and no change is made.

## Patch Rationale

The patch removes the default-rdomain exemption from the privilege condition:

```diff
-if (rtableid != rtid && rtableid != 0 &&
-    (error = suser(p)) != 0)
+if (rtableid != rtid && (error = suser(p)) != 0)
```

This preserves the existing no-op case where `inp->inp_rtableid == rtid`, preserves unprivileged use of the process's own routing table, and requires privilege for every cross-table assignment, including assignments from process routing table `0` to another table.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet6/ip6_output.c b/netinet6/ip6_output.c
index cab02ce..c5027d3 100644
--- a/netinet6/ip6_output.c
+++ b/netinet6/ip6_output.c
@@ -1374,9 +1374,8 @@ do { \
 			rtid = *mtod(m, u_int *);
 			if (inp->inp_rtableid == rtid)
 				break;
-			/* needs privileges to switch when already set */
-			if (rtableid != rtid && rtableid != 0 &&
-			    (error = suser(p)) != 0)
+			/* needs privileges to switch away from process rtable */
+			if (rtableid != rtid && (error = suser(p)) != 0)
 				break;
 			error = in_pcbset_rtableid(inp, rtid);
 			break;
```