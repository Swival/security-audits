# YP named include overflows group line buffer

## Classification

Memory corruption, high severity.

## Affected Locations

`gen/getgrent.c:418`

## Summary

A YP-enabled `/etc/group` named include of the form `+name` can copy an oversized YP `group.byname` record into `struct group_storage.line`, a fixed 1024-byte buffer. The vulnerable branch copies `datalen` bytes with no bounds check and then writes `line[datalen] = '\0'`, so a 1024-byte YP value causes a one-byte out-of-bounds write and larger values overflow the buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- YP support is enabled.
- `/etc/group` contains a named include entry beginning with `+name`.
- A matching YP `group.byname` record is returned.
- The YP record length is at least `sizeof(gs->line)`, i.e. 1024 bytes or more.

## Proof

`gen/getgrent.c` defines `struct group_storage` with `char line[1024]`.

A local `/etc/group` line beginning with `+name` reaches the YP named-include branch in `grscan`. That branch performs:

```c
r = yp_match(__ypdomain, "group.byname", bp, strlen(bp), &data, &datalen);
```

On success, the returned YP value is copied into the fixed buffer:

```c
bcopy(data, line, datalen);
free(data);
line[datalen] = '\0';
```

No bounds check exists before the copy or terminator write.

The reproduced case confirms that `datalen == 1024` is accepted by the YP client path: `yp/xdr_valdat.c` decodes values up to `YPMAXRECORD`, OpenBSD defines `YPMAXRECORD` as 1024, and `yp/ypmatch_cache.c` propagates the decoded length unchanged to `datalen`.

Therefore, a 1024-byte YP value fills `line[0..1023]`, then `line[1024] = '\0'` writes one byte past the buffer. Any `datalen > 1023` is unsafe for the null-terminated parse path.

## Why This Is A Real Bug

The destination buffer is fixed at 1024 bytes, but the YP named-include branch treats the attacker-controlled `datalen` as safe. The subsequent parse requires a trailing NUL byte, so even a record exactly equal to the buffer size is invalid for this storage. With a malicious or compromised YP server, libc callers resolving group data can receive an oversized matching `group.byname` record and suffer memory corruption in-process.

## Fix Requirement

Reject YP records where `datalen >= sizeof(gs->line)` before copying into `line`, because one byte must remain available for the explicit NUL terminator.

## Patch Rationale

The patch adds a length guard immediately after successful `yp_match` in the `+name` named-include branch and before `bcopy`:

```c
if (datalen >= sizeof(gs->line)) {
	free(data);
	continue;
}
```

This preserves existing behavior for valid YP records, avoids truncating group records into malformed partial entries, frees the allocated YP response on rejection, and prevents both the unchecked copy overflow and the out-of-bounds terminator write.

## Residual Risk

None

## Patch

```diff
diff --git a/gen/getgrent.c b/gen/getgrent.c
index 5836485..eaf902f 100644
--- a/gen/getgrent.c
+++ b/gen/getgrent.c
@@ -418,6 +418,10 @@ grscan(int search, gid_t gid, const char *name, struct group *p_gr,
 				default:
 					return 0;
 				}
+				if (datalen >= sizeof(gs->line)) {
+					free(data);
+					continue;
+				}
 				bcopy(data, line, datalen);
 				free(data);
 				line[datalen] = '\0';
```