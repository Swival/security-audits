# peer checksum length overflows block digest buffer

## Classification

Medium severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.bin/rsync/blocks.c:441`

## Summary

`blk_recv()` accepts the peer-controlled checksum length `s->csum` from the block prologue and uses it as the byte count for `io_read_buf()` into `b->chksum_long`. The destination field is fixed-size, but the only pre-patch bounds check is an `assert()`. When assertions are disabled, a malicious peer can set `s->csum` larger than the digest buffer and cause a heap overwrite while block checksums are received.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Assertions are disabled, e.g. `NDEBUG` build.
- The peer controls the rsync block prologue consumed by `blk_recv()`.
- The peer sends a checksum length larger than `sizeof(b->chksum_long)`.

## Proof

`blk_recv()` reads the checksum length from the peer-controlled block prologue:

```c
io_read_size(sess, fd, &s->csum)
```

It then allocates heap-backed `struct blk` entries:

```c
s->blks = calloc(s->blksz, sizeof(struct blk));
```

For each block, the pre-patch code only checks the peer-controlled length with an assertion:

```c
assert(s->csum <= sizeof(b->chksum_long));
```

With assertions disabled, this check is removed. The same unchecked length is then passed to `io_read_buf()` with `b->chksum_long` as the destination:

```c
io_read_buf(sess, fd, b->chksum_long, s->csum)
```

`b->chksum_long` is a fixed 16-byte array in `struct blk` at `usr.bin/rsync/extern.h:189`.

A concrete malicious peer can send a valid regular-file index, followed by a block prologue such as `blksz=1`, valid `len/rem`, and `csum=64`, then one short checksum and 64 checksum bytes. In an `NDEBUG` build, this writes past the 16-byte digest field and past the heap-allocated `struct blk` object. In an assertions-enabled build, the same input aborts the process, producing a peer-triggered denial of service.

Reachability is practical because `rsync_sender()` reads a peer-supplied file index at `usr.bin/rsync/sender.c:495`, validates only the index/file type, and `send_dl_enqueue()` calls `blk_recv()` at `usr.bin/rsync/sender.c:336`.

## Why This Is A Real Bug

The checksum length is attacker-controlled protocol input, but it determines the number of bytes written into a fixed-size heap field. An `assert()` is not a runtime validation mechanism because it is compiled out in release-style builds using `NDEBUG`. Therefore, the vulnerable build performs an unchecked write beyond `b->chksum_long`, corrupting adjacent heap memory before any later validation can reject the input.

## Fix Requirement

Replace the assertion with an unconditional runtime bounds check before calling `io_read_buf()`. If `s->csum` exceeds `sizeof(b->chksum_long)`, reject the block set and exit through the existing cleanup path.

## Patch Rationale

The patch preserves the existing valid input behavior while enforcing the digest-buffer bound in all builds. It rejects oversized peer-provided checksum lengths before any checksum bytes are copied, preventing the heap overwrite. The error path uses the existing `ERRX1()` reporting style and `goto out` cleanup path already used throughout `blk_recv()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rsync/blocks.c b/usr.bin/rsync/blocks.c
index d1d9b19..5b77268 100644
--- a/usr.bin/rsync/blocks.c
+++ b/usr.bin/rsync/blocks.c
@@ -414,7 +414,10 @@ blk_recv(struct sess *sess, int fd, const char *path)
 		}
 		b->chksum_short = i;
 
-		assert(s->csum <= sizeof(b->chksum_long));
+		if (s->csum > sizeof(b->chksum_long)) {
+			ERRX1("inappropriate checksum length");
+			goto out;
+		}
 		if (!io_read_buf(sess,
 		    fd, b->chksum_long, s->csum)) {
 			ERRX1("io_read_buf");
```