# blocked-stream compaction reads past vector

## Classification

Out-of-bounds read. Severity: Low. Confidence: certain.

## Affected Locations

- `lib/http3/qpack.c:430`
- Function: `h2o_qpack_decoder_handle_input`

## Summary

`h2o_qpack_decoder_handle_input` compacts the QPACK decoder blocked-stream vector after previously reporting unblocked streams. The compaction computes `remaining = list.size - num_unblocked`, but incorrectly uses `entries + remaining` as the source pointer for `memmove`.

When `num_unblocked != remaining`, this copies from the wrong offset. In decoder states with nonzero dynamic table capacity, it reads past the end of the allocated vector. The source must be `entries + num_unblocked`.

## Provenance

Verified by Swival security analysis and reproduction. Scanner: https://swival.dev

## Preconditions

- HTTP/3 QPACK decoder is in use.
- Decoder configuration permits blocked streams.
- The decoder has a nonzero dynamic table capacity (`max_entries > 0`).
- QPACK decoder allows at least three blocked streams.
- A peer can send header blocks that reference future dynamic table inserts.
- A peer can send encoder-stream inserts that unblock only a prefix of the blocked-stream list.

Follow-up testing against the stock local `h2o` HTTP/3 server did not satisfy these preconditions for request decoding. The server creates its request QPACK decoder with a zero dynamic table size:

```c
conn->qpack.dec = h2o_qpack_create_decoder(0, 100 /* FIXME */);
```

With `max_entries == 0`, request HEADERS that reference future dynamic inserts are rejected instead of being linked into the blocked-stream list. No stock configuration knob was found that changes this inbound request decoder table size; `quic.qpack-encoder-table-capacity` applies to H2O's response encoder, not this request decoder.

## Proof

The blocked-stream list is sorted by `largest_ref`. Blocked streams are added by `decoder_link_blocked` when `parse_decode_context` sees a Required Insert Count greater than or equal to the current table insert count.

After encoder input is processed, `h2o_qpack_decoder_handle_input` builds a prefix of newly unblocked stream IDs and stores its length in:

```c
qpack->blocked_streams.num_unblocked
```

On the next decoder input, the function attempts to remove that prefix:

```c
size_t remaining = qpack->blocked_streams.list.size - qpack->blocked_streams.num_unblocked;
if (remaining != 0)
    memmove(qpack->blocked_streams.list.entries,
            qpack->blocked_streams.list.entries + remaining,
            sizeof(qpack->blocked_streams.list.entries[0]) * remaining);
```

For `list.size = 3` and `num_unblocked = 1`:

```c
remaining = 2;
memmove(entries, entries + 2, sizeof(entry) * 2);
```

This reads `entries[2]` and `entries[3]`, where `entries[3]` is one past the three-entry logical vector. The source offset should be the number of entries being removed, not the number left behind:

```c
entries + num_unblocked
```

The reproduced ASAN proof used the committed code with nonzero QPACK table size and `max_blocked >= 4`:

1. Submit four peer-controlled header blocks with Required Insert Count `1..4`.
2. Submit one encoder-stream insert so only the first stream unblocks.
3. Call `h2o_qpack_decoder_handle_input` again.

A follow-up local HTTP/3 client test against the default `h2o` server sent the same intended sequence:

```text
client: sent blocking HEADERS stream=0 ric=1 bytes=01020200
client: sent blocking HEADERS stream=4 ric=2 bytes=01020300
client: sent blocking HEADERS stream=8 ric=3 bytes=01020400
client: sent blocking HEADERS stream=12 ric=4 bytes=01020500
client: sent one QPACK insert to unblock first stream
client: sent second QPACK insert to trigger blocked-stream compaction
```

That network test did not reproduce the ASAN overflow because the stock server's inbound request decoder table size is zero, so the blocked-stream vector state required by this proof is not reachable through ordinary request HEADERS on the default server.

ASAN reported:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 72
#1 h2o_qpack_decoder_handle_input qpack.c:423
...
0x608000000380 is located 0 bytes after 96-byte region
allocated by:
#4 decoder_link_blocked qpack.c:275
#5 parse_decode_context qpack.c:795
#6 h2o_qpack_parse_request qpack.c:820
```

## Why This Is A Real Bug

The state is reachable through normal QPACK mechanics when the decoder has a nonzero dynamic table capacity:

- Header blocks can intentionally reference future inserts and become blocked.
- Encoder-stream inserts can unblock only a prefix of the blocked list.
- The next decoder input triggers compaction.
- The wrong `memmove` source offset reads beyond the vector.

This is not a theoretical indexing issue; ASAN confirms a heap-buffer-overflow read in `h2o_qpack_decoder_handle_input` under those decoder settings. However, the default standalone H2O HTTP/3 server currently initializes the inbound request decoder with table size zero, so this specific state was not reproducible through a stock local HTTP/3 client-to-server request path. The impact is therefore most relevant to library/users or configurations/code paths that instantiate the decoder with nonzero table capacity.

## Fix Requirement

When removing the first `num_unblocked` entries from the blocked-stream list, copy the remaining entries from:

```c
entries + num_unblocked
```

not:

```c
entries + remaining
```

## Patch Rationale

The vector contains:

```text
[unblocked prefix of length num_unblocked][remaining suffix of length remaining]
```

Compaction must preserve the suffix by moving it to the beginning. Therefore, the suffix starts at `entries + num_unblocked`.

Using `entries + remaining` only works accidentally when `num_unblocked == remaining`. Otherwise, it copies the wrong elements and can read past the vector.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/http3/qpack.c b/lib/http3/qpack.c
index 1750aa188..f04197f47 100644
--- a/lib/http3/qpack.c
+++ b/lib/http3/qpack.c
@@ -420,7 +420,8 @@ int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, int64_t **unblock
     if (qpack->blocked_streams.num_unblocked != 0) {
         size_t remaining = qpack->blocked_streams.list.size - qpack->blocked_streams.num_unblocked;
         if (remaining != 0)
-            memmove(qpack->blocked_streams.list.entries, qpack->blocked_streams.list.entries + remaining,
+            memmove(qpack->blocked_streams.list.entries,
+                    qpack->blocked_streams.list.entries + qpack->blocked_streams.num_unblocked,
                     sizeof(qpack->blocked_streams.list.entries[0]) * remaining);
         qpack->blocked_streams.list.size = remaining;
         qpack->blocked_streams.num_unblocked = 0;
```