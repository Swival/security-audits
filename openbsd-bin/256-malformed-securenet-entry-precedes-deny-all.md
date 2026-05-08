# Malformed securenet Entry Precedes Deny-All

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`usr.sbin/ypserv/ypserv/acl.c:450`

## Summary

`acl_securenet()` accepted digit-starting securenet mask and network tokens without checking whether `inet_aton()` actually parsed them. A malformed numeric mask such as `999.999.999.999` left `mask.s_addr` as zero, and a numeric zero network parsed as `0`, causing `acl_add_net()` to install an allow `0/0` rule before the file-exists deny-all fallback. Because ACL evaluation returns the first matching rule, the malformed entry bypassed the intended deny-all behavior for all clients.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The securenet file contains an attacker-influenced malformed numeric mask entry.

## Proof

A securenet line such as:

```text
999.999.999.999 0
```

follows this path in `acl_securenet()`:

- The mask token starts with a digit, so the old code called `inet_aton(k, &mask)` and ignored failure.
- Because `mask` was initialized to zero for the line, a failed parse left `mask.s_addr == 0`.
- The network token `0` starts with a digit and parses to zero.
- The old code reached `acl_add_net(allow, &addr, &mask)`, installing allow `0/0`.
- The file-exists deny-all rule was appended later, but after the allow `0/0`.
- `acl_check_host()` returns the first matching rule, so allow `0/0` matched every client first.

Runtime harness evidence reproduced the issue: a valid securenet file allowed only the configured network and denied `203.0.113.42`; a file containing `999.999.999.999 0` returned `parse errors=0` and allowed `203.0.113.42`.

## Why This Is A Real Bug

This is a deterministic fail-open in the securenet ACL parser. Malformed input that should be rejected instead creates an allow-all rule. The later deny-all fallback does not mitigate the issue because ACL matching is first-match and the malformed allow rule is inserted earlier.

## Fix Requirement

`acl_securenet()` must require `inet_aton()` success before advancing parser state or adding securenet mask/network ACL rules. Failed numeric parses must enter an error state and must not call `acl_add_net()`.

## Patch Rationale

The patch checks `inet_aton()` return values for both securenet mask and network tokens. The parser now advances only when `inet_aton()` returns `1`; otherwise it sets `ACLE_NONET`, increments the parse error count through the existing switch path, and prevents malformed numeric entries from installing ACL rules.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/ypserv/acl.c b/usr.sbin/ypserv/ypserv/acl.c
index 2cba27a..e89c5a9 100644
--- a/usr.sbin/ypserv/ypserv/acl.c
+++ b/usr.sbin/ypserv/ypserv/acl.c
@@ -450,8 +450,10 @@ acl_securenet(char *file)
 
 		if (state == ACLS_ALLOW_NET_MASK) {
 			if (*k >= '0' && *k <= '9') {
-				(void)inet_aton(k, &mask);
-				state = ACLS_ALLOW_NET;
+				if (inet_aton(k, &mask) == 1)
+					state = ACLS_ALLOW_NET;
+				else
+					state = ACLE_NONET;
 			} else
 				state = ACLE_NONET;
 
@@ -472,8 +474,10 @@ acl_securenet(char *file)
 
 		if (state == ACLS_ALLOW_NET) {
 			if (*k >= '0' && *k <= '9') {
-				(void)inet_aton(k, &addr);
-				state = ACLS_ALLOW_NET_EOL;
+				if (inet_aton(k, &addr) == 1)
+					state = ACLS_ALLOW_NET_EOL;
+				else
+					state = ACLE_NONET;
 			} else
 				state = ACLE_NONET;
 		}
```