# data token parsing ignores caller buffer limit

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/unwind/libunbound/sldns/parse.c:519`

## Summary

`sldns_bget_keyword_data` accepts a caller-provided `data` buffer and `data_limit`, but ignores `data_limit` when reading the matched data token. It passes `0` to `sldns_bget_token`, disabling bounds checks in `sldns_bget_token_par` and allowing attacker-controlled input to write past the caller buffer.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

Verified with an ASan reproducer against the affected parser path.

## Preconditions

- Caller uses `sldns_bget_keyword_data` with a fixed-size `data` buffer.
- Attacker controls the parsed `sldns_buffer`.
- Input contains a matching keyword followed by data longer than the caller-provided buffer.

## Proof

The vulnerable flow is:

- `sldns_bget_keyword_data(&b, "KEY", " ", data, "\n", sizeof(data))` is called with `data[8]`.
- Input is `KEY AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n`.
- `sldns_bget_keyword_data` reads the keyword token and matches `KEY`.
- It then calls `sldns_bget_token(b, data, d_del, 0)`.
- `sldns_bget_token` dispatches to `sldns_bget_token_par`.
- In `sldns_bget_token_par`, bounds enforcement is guarded by `limit > 0`.
- Because `limit` is `0`, the loop continues writing attacker-controlled bytes via `*t++ = c`.

ASan reports a stack-buffer-overflow at `sbin/unwind/libunbound/sldns/parse.c:404`, reached from the data-token read in `sbin/unwind/libunbound/sldns/parse.c:516`.

## Why This Is A Real Bug

The public function signature explicitly accepts `data_limit`, so callers can reasonably rely on it to bound writes into `data`. The file-based equivalent, `sldns_fget_keyword_data_l`, correctly passes `data_limit` when reading the data token. The buffer-based implementation instead passes `0`, which is documented by implementation behavior as an unbounded parse because all write checks require `limit > 0`.

This creates direct caller memory corruption when the parsed data token exceeds the size of the provided buffer.

## Fix Requirement

Pass `data_limit` to `sldns_bget_token` when filling `data`.

## Patch Rationale

The patch changes only the data-token extraction call in `sldns_bget_keyword_data`:

```c
i = sldns_bget_token(b, data, d_del, data_limit);
```

This preserves existing parsing semantics while enforcing the caller-provided output buffer limit. If the token does not fit, `sldns_bget_token_par` now terminates the buffer and returns `-1` instead of writing past `data`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/libunbound/sldns/parse.c b/sbin/unwind/libunbound/sldns/parse.c
index 8ea0846..40987ab 100644
--- a/sbin/unwind/libunbound/sldns/parse.c
+++ b/sbin/unwind/libunbound/sldns/parse.c
@@ -513,7 +513,7 @@ sldns_bget_keyword_data(sldns_buffer *b, const char *keyword, const char *k_del,
                free(fkeyword);
                /* whee, the match! */
                /* retrieve it's data */
-               i = sldns_bget_token(b, data, d_del, 0);
+               i = sldns_bget_token(b, data, d_del, data_limit);
                return i;
        } else {
                free(fkeyword);
```