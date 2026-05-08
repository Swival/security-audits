# Lease Hostname Quote Injection Corrupts Lease Database Syntax

## Classification

Injection, persistent lease-database statement injection.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.sbin/dhcpd/db.c:127`

`usr.sbin/dhcpd/db.c:132`

`usr.sbin/dhcpd/db.c:138`

`usr.sbin/dhcpd/db.c:143`

## Summary

`write_lease()` writes hostname fields into the persistent DHCP lease database as quoted strings, but the pre-write validation only rejected bytes below `33` or above `126`.

That allowed embedded double quotes and backslashes to pass validation. A double quote could terminate the lease-file string early, letting the remaining attacker-controlled bytes be parsed later as lease-file syntax.

The reproduced attacker-controlled path is `lease->client_hostname`, populated from DHCP option 12. The same unsafe quoted-write pattern also existed for `lease->hostname`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and narrowed to the source-grounded `lease->client_hostname` path, with the same sink pattern confirmed for `lease->hostname`.

## Preconditions

- DHCP server persists leases to the lease database.
- A remote DHCP client can influence the stored hostname value.
- For the reproduced path, the client controls DHCP option 12, which is copied into `lease->client_hostname`.

## Proof

A remote DHCP client can send a hostname payload containing lease-file syntax metacharacters.

Example payload:

```text
x";abandoned;#
```

Before the patch, `write_lease()` accepted the payload because each byte is printable ASCII and therefore passes this validation:

```c
lease->client_hostname[i] < 33 || lease->client_hostname[i] > 126
```

It then wrote the value without escaping:

```c
fprintf(db_file, "\n\tclient-hostname \"%s\";", lease->client_hostname)
```

The resulting lease database fragment becomes syntactically corrupted:

```text
client-hostname "x";abandoned;#";
```

On restart, `db_startup()` calls `read_leases()`, causing the persisted database to be parsed again. The injected `abandoned;` token is then reachable as lease-file syntax and can persistently alter lease state.

## Why This Is A Real Bug

The value is attacker-controlled through DHCP option 12 and reaches `lease->client_hostname`.

The validation intended to restrict unsafe hostname bytes, but printable quote characters are still dangerous in the lease-file grammar because the value is emitted inside double quotes.

The impact is persistent because the corrupted statement is written to disk and parsed later by `read_leases()` during DHCP server startup.

This is not only malformed output; it is statement injection into a configuration-like persistent database format.

## Fix Requirement

Hostname fields written as quoted lease-file strings must not contain unescaped string delimiters or escape characters.

The fix must either:

- reject double quotes and backslashes before writing hostname fields, or
- escape double quotes and backslashes before writing hostname fields.

## Patch Rationale

The patch rejects both `"` and `\` in `lease->client_hostname` and `lease->hostname` before writing either value to the lease database.

This preserves the existing validation model, which already drops hostname fields containing disallowed bytes rather than transforming them.

Rejecting `"` prevents premature termination of the quoted lease-file string.

Rejecting `\` prevents introducing escape-sequence ambiguity if the lease-file parser treats backslash specially inside strings.

The same validation is applied to both hostname fields because both are emitted using the same unsafe quoted-string pattern.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dhcpd/db.c b/usr.sbin/dhcpd/db.c
index 295e522..39119e4 100644
--- a/usr.sbin/dhcpd/db.c
+++ b/usr.sbin/dhcpd/db.c
@@ -127,7 +127,9 @@ write_lease(struct lease *lease)
 	if (lease->client_hostname) {
 		for (i = 0; lease->client_hostname[i]; i++)
 			if (lease->client_hostname[i] < 33 ||
-			    lease->client_hostname[i] > 126)
+			    lease->client_hostname[i] > 126 ||
+			    lease->client_hostname[i] == '"' ||
+			    lease->client_hostname[i] == '\\')
 				goto bad_client_hostname;
 		if (fprintf(db_file, "\n\tclient-hostname \"%s\";",
 		    lease->client_hostname) == -1)
@@ -138,7 +140,9 @@ bad_client_hostname:
 	if (lease->hostname) {
 		for (i = 0; lease->hostname[i]; i++)
 			if (lease->hostname[i] < 33 ||
-			    lease->hostname[i] > 126)
+			    lease->hostname[i] > 126 ||
+			    lease->hostname[i] == '"' ||
+			    lease->hostname[i] == '\\')
 				goto bad_hostname;
 		if (fprintf(db_file, "\n\thostname \"%s\";",
 		    lease->hostname) == -1)
```