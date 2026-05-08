# Oversized Remote Identifier Aborts rsync

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/rsync/ids.c:301`

## Summary

A malicious rsync peer can send a remote UID/GID identifier value at or above `INT32_MAX` while identifier name lists are enabled. The receiver reads the attacker-controlled value as `uint32_t`, then reaches `assert(id < INT32_MAX)` before storing it into the signed `struct ident.id` field. This aborts the receiver process instead of rejecting malformed input.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Originally reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The receiver must preserve remote user or group identifiers.

This is reachable when UID/GID name lists are enabled, such as with `-o`, `-g`, or `-a`, and `--numeric-ids` is not used.

## Proof

The vulnerable path is:

- A pulling client enters `rsync_receiver` at `usr.bin/rsync/client.c:91`.
- The receiver reads the peer file list at `usr.bin/rsync/receiver.c:224`.
- With preserved IDs and without numeric IDs, `flist_recv` calls `idents_recv` for UID/GID lists at `usr.bin/rsync/flist.c:742` and `usr.bin/rsync/flist.c:750`.
- `idents_recv` reads an attacker-controlled identifier into `uint32_t id` at `usr.bin/rsync/ids.c:275`.
- For every nonzero `id`, it reallocates the identifier list and reads the name length.
- It then executes `assert(id < INT32_MAX)` at `usr.bin/rsync/ids.c:301`.
- A peer that sends `0x7fffffff` or larger deterministically trips the assertion.
- The committed rsync Makefile only adds warning flags and does not disable assertions at `usr.bin/rsync/Makefile:11`.

Trigger bytes after the file-list terminator include an identifier-list entry with little-endian ID `0x7fffffff` or larger, followed by any length byte.

## Why This Is A Real Bug

The identifier value is peer-controlled input from the rsync protocol stream. Assertions are not appropriate for validating adversarial input because a failed assertion terminates the process. Here, the receiver has enough context to reject the malformed identifier with a normal parse error, but instead aborts.

The abort is deterministic for IDs `>= INT32_MAX` when the identifier list is parsed, causing denial of service of the receiver process.

## Fix Requirement

Reject oversized remote identifier IDs before assignment to the signed `struct ident.id` field.

The rejection must be handled as a normal protocol parse failure, not as an assertion failure.

## Patch Rationale

The patch replaces the fatal assertion with an explicit runtime validation:

```c
if (id >= INT32_MAX) {
	ERRX("identifier id too large: %u", id);
	return 0;
}
```

This preserves the existing invariant that stored identifiers fit in the signed field while making malformed remote input fail cleanly through the function’s existing error-return path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rsync/ids.c b/usr.bin/rsync/ids.c
index 1eef94b..97c00e9 100644
--- a/usr.bin/rsync/ids.c
+++ b/usr.bin/rsync/ids.c
@@ -299,7 +299,10 @@ idents_recv(struct sess *sess,
 		} else if (sz == 0)
 			WARNX("zero-length name in identifier list");
 
-		assert(id < INT32_MAX);
+		if (id >= INT32_MAX) {
+			ERRX("identifier id too large: %u", id);
+			return 0;
+		}
 		(*ids)[*idsz].id = id;
 		(*ids)[*idsz].name = calloc(sz + 1, 1);
 		if ((*ids)[*idsz].name == NULL) {
```