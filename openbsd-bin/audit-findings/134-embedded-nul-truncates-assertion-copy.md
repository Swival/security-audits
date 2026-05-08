# Embedded NUL Truncates Assertion Copy

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`lib/libkeynote/parse_assertion.c:387`

## Summary

`keynote_parse_assertion` accepts a caller-provided buffer plus explicit `len`, but copied the buffer with `strdup(buf)`. If `buf` contains an embedded NUL before `len`, `strdup` allocates only the prefix through that NUL while the parser continues to use the original `len` as its parsing bound. Subsequent indexing into `as->as_buf[i]` can read past the truncated heap allocation.

## Provenance

Verified from the supplied source, reproduced with ASan, and patched according to the provided fix outline.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- A caller passes an attacker-controlled assertion buffer to `keynote_parse_assertion`.
- The caller supplies an explicit `len` covering bytes beyond an embedded NUL.
- The buffer is parsed through normal KeyNote assertion parsing paths such as `kn_add_assertion` / `kn_query`.

## Proof

The vulnerable code copied the assertion with:

```c
as->as_buf = strdup(buf);
```

`strdup` stops at the first NUL byte. The parser then keeps:

```c
for (i = 0, j = len; i < j && isspace((unsigned char)as->as_buf[i]); i++)
```

and later continues scanning while `i < j`, including the keyword separator loop:

```c
for (; (as->as_buf[i] != ':') && (i < j); i++)
  ;
```

A payload such as:

```text
keynote-version\0: 2
authorizer: "POLICY"
```

with `len` covering the full buffer causes `as->as_buf` to contain only the prefix up to the embedded NUL, while `j` still covers the complete attacker-supplied length. During the scan for `:`, `i` advances past the truncated `strdup` allocation and reads out of bounds.

The reproducer confirmed this with ASan: `heap-buffer-overflow` on a read at `lib/libkeynote/parse_assertion.c:428`, immediately after the truncated allocation made by `strdup`.

## Why This Is A Real Bug

The function’s contract uses an explicit length, so embedded NUL bytes are valid input bytes from the memory-safety perspective and must not shorten the backing allocation. The parser consistently treats `len` as authoritative, making `strdup` the mismatch that creates the out-of-bounds read. The issue is reachable from public assertion ingestion paths when applications pass peer-controlled buffers and their received lengths.

## Fix Requirement

Copy exactly `len` bytes into a newly allocated buffer of size `len + 1`, then append a terminating NUL byte for code that expects string termination. Reject negative lengths before converting `len` to `size_t`.

## Patch Rationale

The patch replaces `strdup(buf)` with an explicit length-preserving allocation and copy:

```c
if (len < 0)
{
	keynote_free_assertion(as);
	keynote_errno = ERROR_SYNTAX;
	return NULL;
}

as->as_buf = malloc((size_t)len + 1);
if (as->as_buf == NULL)
{
	keynote_errno = ERROR_MEMORY;
	keynote_free_assertion(as);
	return NULL;
}
memcpy(as->as_buf, buf, (size_t)len);
as->as_buf[len] = '\0';
```

This makes the allocation match the parser’s `len` bound, preserves embedded NUL bytes inside the assertion copy, and still provides a trailing NUL sentinel after the explicit buffer. The negative-length guard prevents signed-to-unsigned conversion from producing a huge allocation size.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/parse_assertion.c b/lib/libkeynote/parse_assertion.c
index 59dd7d1..a104c1e 100644
--- a/lib/libkeynote/parse_assertion.c
+++ b/lib/libkeynote/parse_assertion.c
@@ -380,13 +380,22 @@ keynote_parse_assertion(char *buf, int len, int assertion_flags)
     }
 
     /* Keep a copy of the assertion around */
-    as->as_buf = strdup(buf);
+    if (len < 0)
+    {
+	keynote_free_assertion(as);
+	keynote_errno = ERROR_SYNTAX;
+	return NULL;
+    }
+
+    as->as_buf = malloc((size_t)len + 1);
     if (as->as_buf == NULL)
     {
 	keynote_errno = ERROR_MEMORY;
 	keynote_free_assertion(as);
 	return NULL;
     }
+    memcpy(as->as_buf, buf, (size_t)len);
+    as->as_buf[len] = '\0';
 
     as->as_flags = assertion_flags & ~(ASSERT_FLAG_SIGGEN |
 				       ASSERT_FLAG_SIGVER);
```