# YP wildcard lookup overflows group line buffer

## Classification

Memory corruption, high severity. Confidence: certain.

## Affected Locations

`gen/getgrent.c:384`

Also affected by the same unchecked YP record copy pattern:

`gen/getgrent.c:328`

`gen/getgrent.c:421`

## Summary

When libc is built with YP support, group lookup code can copy an attacker-controlled YP group record into `gs->line`, a fixed 1024-byte buffer, without first validating the returned YP value length. A malicious YP server can return a record with `datalen >= sizeof(gs->line)`, causing `bcopy(data, line, datalen)` and the subsequent `line[datalen] = '\0'` terminator write to corrupt adjacent memory in the caller process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from the provided source by tracing the YP lookup paths in `grscan()` and confirming that YP-supplied `datalen` reaches fixed-buffer copies without bounds checks.

## Preconditions

- libc is built with `YP` enabled.
- `/etc/group` contains a YP `+` entry.
- The process performs affected group lookups or enumeration.
- The configured YP server is malicious or otherwise able to return an oversized group record.

## Proof

In `grscan()`, local group lines beginning with `+` trigger YP lookups.

For wildcard `+` entries, `yp_match()` is called against `group.byname` or `group.bygid`. On success, the returned `data` and `datalen` are copied directly:

```c
bcopy(data, line, datalen);
free(data);
line[datalen] = '\0';
```

Here, `line` is `gs->line`, defined as:

```c
#define MAXLINELENGTH 1024
char line[MAXLINELENGTH];
```

No check rejects `datalen >= sizeof(gs->line)` before either the copy or the terminator write. Therefore:

- `datalen > 1024` overflows during `bcopy()`.
- `datalen == 1024` causes a one-byte out-of-bounds NUL write at `line[1024]`.

The same unchecked pattern is reachable through:

- YP enumeration via `yp_first()` / `yp_next()`.
- wildcard `+` lookup by name or gid.
- `+name` lookup via `yp_match()` against `group.byname`.

## Why This Is A Real Bug

The YP value length is supplied by the YP response and propagated to the caller as `datalen`. The destination buffer is a fixed 1024-byte member of `struct group_storage`. The code explicitly writes a NUL terminator at `line[datalen]`, which requires `datalen < sizeof(gs->line)`.

Because that invariant was not enforced, an oversized YP record corrupts memory inside the libc caller process. For non-reentrant callers, this affects libc static/thread-private group storage. For reentrant callers, this can write beyond the caller-provided buffer that passed the `_GR_BUF_LEN` size check.

## Fix Requirement

Reject any YP record where `datalen >= sizeof(gs->line)` before copying `data` into `line` or writing the terminating NUL byte.

The YP response buffer must be freed on rejection.

## Patch Rationale

The patch adds the required bounds check at each YP-to-`line` copy site:

```c
if (datalen >= sizeof(gs->line)) {
	free(data);
	continue;
}
```

This preserves existing behavior for valid records, skips oversized records consistently with local oversized group-line handling, and prevents both the overflowing copy and the out-of-bounds terminator write.

## Residual Risk

None

## Patch

```diff
diff --git a/gen/getgrent.c b/gen/getgrent.c
index 5836485..22b6804 100644
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
@@ -384,6 +388,10 @@ grscan(int search, gid_t gid, const char *name, struct group *p_gr,
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
@@ -418,6 +426,10 @@ grscan(int search, gid_t gid, const char *name, struct group *p_gr,
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