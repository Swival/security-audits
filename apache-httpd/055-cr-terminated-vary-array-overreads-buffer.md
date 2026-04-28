# CR-Terminated Vary Array Overreads Buffer

## Classification

Memory safety, medium severity, certain confidence.

## Affected Locations

`modules/cache/mod_cache_socache.c:152`

## Summary

`read_array()` reads one byte beyond the retrieved socache object when a cached vary-format entry ends with `\r` as the final byte. The parser increments `*slider` past the CR and then checks `buffer[*slider]` for an optional LF without first confirming that `*slider < buffer_len`.

## Provenance

Verified from the supplied source, reproduced with an ASan harness, and patched according to the Swival Security Scanner finding.

Scanner: https://swival.dev

## Preconditions

- The retrieved socache entry uses `CACHE_SOCACHE_VARY_FORMAT_VERSION`.
- The vary array payload is malformed or corrupted such that the final retrieved byte is `\r`.
- `open_entity()` reaches `read_array()` before cache validation rejects the entry.

## Proof

`open_entity()` retrieves the cached object into `sobj->buffer` and receives the trusted retrieved length in `buffer_len`.

For vary-format entries, `open_entity()` calls:

```c
rc = read_array(r, varray, sobj->buffer, buffer_len, &slider);
```

Inside `read_array()`, the loop condition only guarantees that the current read is in bounds:

```c
while (*slider < buffer_len) {
    if (buffer[*slider] == '\r') {
```

When the CR is not an empty terminator, the function pushes the preceding element, increments `*slider`, and immediately reads the optional LF:

```c
(*slider)++;
if (buffer[*slider] == '\n') {
    (*slider)++;
}
```

For input equivalent to `"A\r"` with `buffer_len == 2`, `*slider` is `1` at the CR, then becomes `2`, and `buffer[2]` is read one byte past the retrieved object.

The supplied reproducer confirmed this behavior with an ASan harness using the same `read_array()` logic.

## Why This Is A Real Bug

The out-of-bounds access is relative to `buffer_len`, the length returned by the socache provider for the retrieved object. Although `sobj->buffer` is allocated to `dconf->max`, bytes beyond `buffer_len` are outside the valid retrieved entry and may contain unrelated or uninitialized APR allocation contents.

Apache’s normal `store_array()` emits `CRLF`, so its own writer should not generate this malformed exact ending. However, the parser accepts externally supplied or corrupted socache contents, and this malformed cache object is reachable during vary-entry parsing before later cache validation.

## Fix Requirement

Before reading the optional LF after a CR, `read_array()` must verify that `*slider` is still less than `buffer_len`.

## Patch Rationale

The patch preserves existing parsing behavior for well-formed `CRLF` and bare-CR-delimited entries while preventing the single unsafe read when CR is the final retrieved byte.

It changes only the optional-LF check:

```c
if (*slider < buffer_len && buffer[*slider] == '\n') {
```

This keeps the parser from dereferencing `buffer[*slider]` after `*slider` has advanced to `buffer_len`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_socache.c b/modules/cache/mod_cache_socache.c
index 38f1bfb..52d48d4 100644
--- a/modules/cache/mod_cache_socache.c
+++ b/modules/cache/mod_cache_socache.c
@@ -150,7 +150,7 @@ static apr_status_t read_array(request_rec *r, apr_array_header_t *arr,
             *((const char **) apr_array_push(arr)) = apr_pstrndup(r->pool,
                     (const char *) buffer + val, *slider - val);
             (*slider)++;
-            if (buffer[*slider] == '\n') {
+            if (*slider < buffer_len && buffer[*slider] == '\n') {
                 (*slider)++;
             }
             val = *slider;
```