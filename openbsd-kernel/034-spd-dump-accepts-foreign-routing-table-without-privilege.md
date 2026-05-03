# SPD dump accepts foreign routing table without privilege

## Classification

Information disclosure, medium severity, confidence certain.

## Affected Locations

`net/pfkeyv2.c:2117`

## Summary

`pfkeyv2_sysctl` allows an unprivileged local caller to request `NET_KEY_SPD_DUMP` for an arbitrary existing routing table supplied as `name[2]`. The handler validates only that the table exists, derives its rdomain, and walks that rdomain's SPD without requiring privilege. This discloses foreign rdomain IPsec policy selectors and actions.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A foreign routing table exists.
- The foreign routing table's rdomain contains SPD policies.
- A lower-privileged local process can issue the PF_KEY sysctl read request.

## Proof

A lower-privileged local process can issue a PF_KEY sysctl read equivalent to:

```c
{ PF_KEY_V2, NET_KEY_SPD_DUMP, SADB_SATYPE_UNSPEC, foreign_tableid }
```

The path is reachable because `sys_sysctl` requires `suser()` for writes, not reads, and `net_sysctl` dispatches the PF_KEY request to `pfkeyv2_sysctl`.

In `pfkeyv2_sysctl`, when `namelen == 3`, `name[2]` is accepted as `tableid`. The code checks only `rtable_exists(tableid)`, then derives:

```c
rdomain = rtable_l2(tableid);
```

For `NET_KEY_SADB_DUMP`, the handler requires:

```c
if ((error = suser(curproc)) != 0)
	return (error);
```

For `NET_KEY_SPD_DUMP`, the vulnerable code omits that check and directly walks the selected SPD:

```c
NET_LOCK_SHARED();
error = spd_table_walk(rdomain, pfkeyv2_sysctl_policydumper, &w);
NET_UNLOCK_SHARED();
```

`pfkeyv2_sysctl_policydumper` calls `pfkeyv2_dump_policy`, prepends a PF_KEY message header, and copies the result to userland with `copyout`. `pfkeyv2_dump_policy` exports policy data through `export_flow`, including policy action/type, direction, protocol, source and destination flows, and masks.

## Why This Is A Real Bug

The code explicitly supports selecting a routing table by sysctl name component, but `NET_KEY_SPD_DUMP` does not enforce either privilege or caller-rdomain confinement before dumping the selected SPD.

This creates a direct privilege boundary bypass: a lower-privileged local process can disclose IPsec policy metadata from another rdomain without opening a privileged PF_KEY socket. The disclosure includes selectors and policy actions, which are security-relevant configuration details.

The adjacent `NET_KEY_SADB_DUMP` case already requires `suser(curproc)`, demonstrating that dumping PF_KEY security state is intended to be privileged.

## Fix Requirement

Require privilege before serving `NET_KEY_SPD_DUMP`, or otherwise restrict unprivileged SPD dumps to the caller's own routing table. The applied patch uses the stricter and consistent behavior: require `suser(curproc)` for SPD dumps.

## Patch Rationale

The patch adds the same privilege check used by `NET_KEY_SADB_DUMP` to the `NET_KEY_SPD_DUMP` case before walking the SPD table.

This prevents unprivileged callers from dumping SPD policies from any routing table, including foreign rdomains selected through `name[2]`. It also aligns SPD dump access control with SADB dump access control in the same function.

## Residual Risk

None

## Patch

```diff
diff --git a/net/pfkeyv2.c b/net/pfkeyv2.c
index b680611..ebf5096 100644
--- a/net/pfkeyv2.c
+++ b/net/pfkeyv2.c
@@ -2738,6 +2738,8 @@ pfkeyv2_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
 		break;
 
 	case NET_KEY_SPD_DUMP:
+		if ((error = suser(curproc)) != 0)
+			return (error);
 		NET_LOCK_SHARED();
 		error = spd_table_walk(rdomain,
 		    pfkeyv2_sysctl_policydumper, &w);
```