# YP enumeration overflows group line buffer

## Classification

Memory corruption; high severity.

## Affected Locations

`gen/getgrent.c:325`

## Summary

When YP support is enabled, group enumeration can copy an attacker-controlled `group.byname` record into a fixed 1024-byte buffer without checking its length. A malicious YP server can return a valid maximum-sized record where `datalen == 1024`, causing `line[datalen] = '\0'` to write one byte past `gs->line`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- YP support is enabled.
- `/etc/group` enumeration reaches a `+` entry.
- The process performs `getgrent()` or `_getgrent_yp()` group enumeration.
- A malicious or compromised YP server controls the returned `group.byname` record.

## Proof

`grscan()` enters YP enumeration mode when a `+` group entry is reached and `search == 0`. In that mode, it calls `yp_first()` or `yp_next()` on `group.byname`, receiving attacker-controlled `data` and `datalen`.

The vulnerable path then performs:

```c
bcopy(data, line, datalen);
free(data);
line[datalen] = '\0';
```

`line` points to `gs->line`, which is declared as:

```c
#define MAXLINELENGTH 1024
char line[MAXLINELENGTH];
```

No bounds check occurs before the copy or terminator write. The YP/RPC layer permits this exact boundary case: values are decoded up to `YPMAXRECORD`, and OpenBSD’s YP protocol defines `YPMAXRECORD` as `1024`. Therefore, a malicious YP server can return a valid 1024-byte record.

For `datalen == 1024`:

- `bcopy(data, line, datalen)` fills `line[0]` through `line[1023]`.
- `line[datalen] = '\0'` writes to `line[1024]`.
- `line[1024]` is one byte past the fixed buffer.

## Why This Is A Real Bug

The input is network-controlled through YP, reaches libc group enumeration, and is copied into fixed-size thread-private storage without validating that space remains for the trailing NUL byte. The overflow is reachable through normal `getgrent()` / `_getgrent_yp()` use on YP-enabled systems whose group file contains a `+` enumeration marker.

This is not prevented by YP protocol limits because the protocol allows a 1024-byte record, while the local destination buffer is exactly 1024 bytes and the code additionally writes a terminator.

## Fix Requirement

Reject or safely skip YP records where `datalen >= sizeof(gs->line)` before copying into `gs->line` or writing the NUL terminator.

## Patch Rationale

The patch adds a bounds check immediately after successful `yp_first()` / `yp_next()` retrieval and before `bcopy()`:

```c
if (datalen >= sizeof(gs->line)) {
	free(data);
	continue;
}
```

This preserves existing behavior for valid records that fit, ensures one byte remains for the trailing NUL, frees the YP-allocated data on rejection, and continues enumeration rather than corrupting memory or aborting the entire lookup.

## Residual Risk

None

## Patch

```diff
diff --git a/gen/getgrent.c b/gen/getgrent.c
index 5836485..8e9f7cc 100644
--- a/gen/getgrent.c
+++ b/gen/getgrent.c
@@ -325,6 +325,10 @@ grscan(int search, gid_t gid, const char *name, struct group *p_gr,
 				else
 					return 0;
 			}
+			if (datalen >= sizeof(gs->line)) {
+				free(data);
+				continue;
+			}
 			bcopy(data, line, datalen);
 			free(data);
 			line[datalen] = '\0';
```