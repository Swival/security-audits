# Malformed ACL Netmask Installs Allow-All

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`usr.sbin/ypserv/ypserv/acl.c:328`

## Summary

`ypserv` ACL parsing accepted a malformed `netmask` token for `allow net` rules because `acl_init()` ignored the return value from `inet_aton()`. A rejected netmask left `mask.s_addr` at `0`, then installed an ACL entry with address `0` and mask `0`. Since ACL matching checks `(client & mask) == stored_addr`, that entry matches every remote host and returns `allow` before later deny rules.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`ypserv` loads an attacker-influenced ACL file.

## Proof

A reproduced ACL file:

```text
allow net 0 netmask 999.999.999.999
deny all
```

Observed behavior before the patch:

- `net` value `0` was accepted and left `addr.s_addr == 0`.
- `inet_aton(k, &mask)` rejected `999.999.999.999`, but its failure was ignored.
- `mask.s_addr` remained initialized to `0`.
- End-of-line handling called `acl_add_net()` with `(addr=0, mask=0)`.
- `acl_check_host()` matched unrelated client addresses because `(addr->s_addr & 0) == 0`.
- The reproduced driver returned `errors=0` and allowed unrelated client addresses despite the following `deny all`.

## Why This Is A Real Bug

This is a deterministic fail-open access-control bypass. The malformed ACL line is not rejected, no parse error is counted, and the installed `(0, 0)` allow rule matches every client. Because ACL entries are evaluated in order, the malformed allow rule takes precedence over later deny rules and disables the intended host access restriction.

## Fix Requirement

`acl_init()` must only advance to the netmask end-of-line state when `inet_aton()` successfully parses the supplied netmask. Invalid numeric-looking netmask tokens must be treated as parse errors and must not install an ACL entry.

## Patch Rationale

The patch changes the netmask parser condition from “token starts with a digit” to “token starts with a digit and `inet_aton()` succeeds.” This preserves existing acceptance of valid IPv4 netmasks while routing malformed netmasks to the existing `ACLE_NONET` error path. Because the state no longer advances to `ACLS_ALLOW_NET_EOL` or `ACLS_DENY_NET_EOL` on parse failure, `acl_add_net()` is not called for the malformed rule.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/ypserv/acl.c b/usr.sbin/ypserv/ypserv/acl.c
index 2cba27a..dd39584 100644
--- a/usr.sbin/ypserv/ypserv/acl.c
+++ b/usr.sbin/ypserv/ypserv/acl.c
@@ -327,8 +327,8 @@ acl_init(char *file)
 
 			if (state == ACLS_ALLOW_NET_MASK ||
 			    state == ACLS_DENY_NET_MASK) {
-				if (*k >= '0' && *k <= '9') {
-					(void)inet_aton(k, &mask);
+				if (*k >= '0' && *k <= '9' &&
+				    inet_aton(k, &mask) != 0) {
 					state = state + ACLD_NET_EOL;
 				} else
 					state = ACLE_NONET;
```