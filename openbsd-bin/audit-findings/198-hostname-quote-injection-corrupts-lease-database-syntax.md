# Hostname Quote Injection Corrupts Lease Database Syntax

## Classification

Injection, persistent lease-database statement injection.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.sbin/dhcpd/db.c:132`

## Summary

`write_lease()` serializes `lease->client_hostname` into the persistent DHCP lease database inside double quotes, but the pre-write validation only rejected bytes below 33 or above 126. As a result, attacker-controlled double quotes, backslashes, semicolons, braces, and comment markers could be written into lease-file syntax unescaped.

A remote DHCP client that controls the hostname option could inject persistent lease statements that are later parsed as real lease metadata on database reload.

## Provenance

Verified by reproduced analysis and patched from Swival Security Scanner output.

Scanner: https://swival.dev

## Preconditions

- `dhcpd` records attacker-supplied `client_hostname` in a lease.
- The lease is written to the persistent lease database.
- The lease database is later rewritten and re-read.

## Proof

The original validation at `usr.sbin/dhcpd/db.c:127` rejected only bytes `< 33` or `> 126`, allowing metacharacters such as `"`, `;`, `{`, `}`, `#`, and `\`.

The value was then emitted directly at `usr.sbin/dhcpd/db.c:132`:

```c
fprintf(db_file, "\n\tclient-hostname \"%s\";", lease->client_hostname)
```

A practical attacker-controlled hostname such as:

```text
x";uid"evil";abandoned;#
```

serializes as:

```text
client-hostname "x";uid"evil";abandoned;#";
```

On lease-file reload, the injected quote terminates the string and `#` begins a comment. The parser can then process attacker-supplied `uid` and `abandoned` tokens as lease statements, poisoning persistent lease state.

## Why This Is A Real Bug

The affected value is attacker-influenced DHCP client input and is written into a trusted persistent database format without escaping lease-file string delimiters.

The impact persists beyond the current packet handling path because the corrupted syntax is stored on disk and interpreted during later lease database parsing. This allows untrusted client input to alter lease ownership or flags across rewrite and reload.

## Fix Requirement

The lease writer must prevent unescaped lease-file metacharacters from appearing inside quoted string fields.

At minimum, `client_hostname` must reject or escape:

- `"` because it terminates the quoted lease-file string.
- `\` because it can affect string interpretation and future escaping semantics.

## Patch Rationale

The patch rejects double quotes and backslashes during the existing `client_hostname` validation pass:

```diff
 if (lease->client_hostname[i] < 33 ||
-    lease->client_hostname[i] > 126)
+    lease->client_hostname[i] > 126 ||
+    lease->client_hostname[i] == '"' ||
+    lease->client_hostname[i] == '\\')
        goto bad_client_hostname;
```

This preserves the existing behavior of omitting invalid `client-hostname` fields rather than changing lease-file serialization semantics. It blocks the quote-termination primitive required for statement injection and avoids writing ambiguous backslashes into quoted lease strings.

## Residual Risk

None

## Patch

`198-hostname-quote-injection-corrupts-lease-database-syntax.patch`

```diff
diff --git a/usr.sbin/dhcpd/db.c b/usr.sbin/dhcpd/db.c
index 295e522..37ba142 100644
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
```