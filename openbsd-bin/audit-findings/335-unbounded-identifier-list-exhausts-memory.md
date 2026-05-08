# Unbounded Identifier List Exhausts Memory

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/rsync/ids.c:280`

## Summary

`idents_recv()` accepts an attacker-controlled stream of uid/gid identifier records and only stops when the peer sends `id == 0`. A malicious rsync sender can continuously send valid nonzero identifier records without the terminator, causing the receiver to repeatedly grow the identifier array and allocate name buffers until memory is exhausted.

## Provenance

Verified and reproduced from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- The receiver preserves uid or gid identifiers from the peer.
- `idents_recv()` is reached when `preserve_uids` or `preserve_gids` is enabled and `numeric_ids` is disabled.
- Archive mode enables both uid and gid preservation.

## Proof

- A malicious sender can send a file-list terminator, then stream identifier records with any nonzero `id`.
- `idents_recv()` loops with `for (;;)`.
- The loop exits only when `io_read_uint()` returns `id == 0`.
- For each nonzero identifier, `idents_recv()` calls `reallocarray(*ids, *idsz + 1, sizeof(struct ident))`.
- It then allocates a per-entry name buffer with `calloc(sz + 1, 1)`.
- `*idsz` is incremented after each accepted record.
- The one-byte name length limits each individual name, but does not limit the number of entries.
- Without a terminator, a continuously sending peer can force unbounded receiver memory growth until allocation failure or system memory pressure.

## Why This Is A Real Bug

The identifier list is fully controlled by the peer and has no count or byte-budget limit. The receiver performs one array growth and one name allocation for every nonzero record before seeing a terminator. Because the protocol permits the peer to continue sending nonzero records indefinitely, the receiver’s memory consumption is attacker-amplifiable and unbounded under the stated preconditions.

## Fix Requirement

Enforce a maximum identifier count or equivalent receive-side byte budget before allocating storage for another identifier record.

## Patch Rationale

The patch defines `MAX_IDENTS` as `UINT16_MAX` and checks `*idsz >= MAX_IDENTS` immediately after reading a nonzero identifier and before any additional allocation. This preserves normal terminated identifier-list handling while bounding the maximum number of entries a peer can force the receiver to store. On excess input, the receiver reports `too many identifiers` and aborts the receive path instead of continuing to allocate memory.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rsync/ids.c b/usr.bin/rsync/ids.c
index 1eef94b..6102f1d 100644
--- a/usr.bin/rsync/ids.c
+++ b/usr.bin/rsync/ids.c
@@ -25,6 +25,8 @@
 
 #include "extern.h"
 
+#define MAX_IDENTS	UINT16_MAX
+
 /*
  * Free a list of struct ident previously allocated with idents_add().
  * Does nothing if the pointer is NULL.
@@ -277,6 +279,10 @@ idents_recv(struct sess *sess,
 			return 0;
 		} else if (id == 0)
 			break;
+		else if (*idsz >= MAX_IDENTS) {
+			ERRX("too many identifiers");
+			return 0;
+		}
 
 		pp = reallocarray(*ids,
 			*idsz + 1, sizeof(struct ident));
```