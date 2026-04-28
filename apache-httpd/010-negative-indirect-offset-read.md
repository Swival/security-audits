# Negative Indirect Offset Read

## Classification

Memory safety, high severity. Confidence: certain.

## Affected Locations

`modules/metadata/mod_mime_magic.c:1817`

## Summary

`mod_mime_magic` accepted negative direct and indirect magic offsets, then performed a bounds check that only rejected offsets whose end exceeded `nbytes`. For negative offsets, `offset + sizeof(union VALUETYPE) > nbytes` can be false, allowing `memcpy()` to read from `s + offset` before the input buffer.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A configured magic rule uses either:

- a negative direct offset, or
- an indirect offset expression that computes a negative offset.

## Proof

Magic file offsets are parsed with `strtol()` into signed fields:

- `m->offset`
- `m->in.offset`

Negative values are not rejected during parsing.

Reachability is practical through request type checking:

```text
magic_find_ct() -> magic_process() -> tryit() -> softmagic() -> match() -> mget()
```

A direct trigger is:

```text
-1 byte x application/x-poc
```

For a regular file where `nbytes >= sizeof(union VALUETYPE) - 1`, the original check does not reject `offset = -1`, and `memcpy()` reads from `s - 1`.

An indirect trigger is:

```text
0 byte x application/x-poc
>(0.b-1) byte x underflow
```

With first byte `0`, the continuation computes:

```text
offset = p->b + (-1)
```

This produces `offset = -1` and reaches the same pre-buffer read.

An extracted PoC matching the committed `mget()` logic with `offset = -1` was compiled with AddressSanitizer, which reported a stack-buffer-underflow on the `memcpy()` read from one byte before the buffer.

## Why This Is A Real Bug

The vulnerable check only validates the upper bound after adding the object size:

```c
if (offset + sizeof(union VALUETYPE) > nbytes)
    return 0;
```

It does not validate that `offset >= 0`. Because `offset` is signed, negative values can pass this check and are then used in pointer arithmetic:

```c
memcpy(p, s + offset, sizeof(union VALUETYPE));
```

This is an out-of-bounds read before the buffer and is reachable from configured magic rules during normal MIME type detection.

## Fix Requirement

Reject negative offsets and perform overflow-safe bounds validation before each `memcpy()`:

```text
offset >= 0
nbytes >= sizeof(union VALUETYPE)
offset <= nbytes - sizeof(union VALUETYPE)
```

The same validation is required for both the initial offset and the computed indirect offset.

## Patch Rationale

The patch adds explicit lower-bound validation and rewrites the upper-bound check to avoid signed addition and underflow hazards:

```c
if (offset < 0 || nbytes < sizeof(union VALUETYPE) ||
    (apr_size_t)offset > nbytes - sizeof(union VALUETYPE))
    return 0;
```

This prevents:

- negative offsets from forming pointers before `s`
- `nbytes - sizeof(union VALUETYPE)` underflow
- signed `offset + sizeof(...)` arithmetic from masking invalid offsets

The same guard is applied before both `memcpy()` calls in `mget()`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/metadata/mod_mime_magic.c b/modules/metadata/mod_mime_magic.c
index 1c96db4..f56867f 100644
--- a/modules/metadata/mod_mime_magic.c
+++ b/modules/metadata/mod_mime_magic.c
@@ -1786,7 +1786,8 @@ static int mget(request_rec *r, union VALUETYPE *p, unsigned char *s,
 {
     long offset = m->offset;
 
-    if (offset + sizeof(union VALUETYPE) > nbytes)
+    if (offset < 0 || nbytes < sizeof(union VALUETYPE) ||
+        (apr_size_t)offset > nbytes - sizeof(union VALUETYPE))
                   return 0;
 
     memcpy(p, s + offset, sizeof(union VALUETYPE));
@@ -1808,7 +1809,8 @@ static int mget(request_rec *r, union VALUETYPE *p, unsigned char *s,
             break;
         }
 
-        if (offset + sizeof(union VALUETYPE) > nbytes)
+        if (offset < 0 || nbytes < sizeof(union VALUETYPE) ||
+            (apr_size_t)offset > nbytes - sizeof(union VALUETYPE))
                       return 0;
 
         memcpy(p, s + offset, sizeof(union VALUETYPE));
```