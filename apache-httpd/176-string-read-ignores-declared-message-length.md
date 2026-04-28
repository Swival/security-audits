# string read ignores declared message length

## Classification

Validation gap; medium severity.

## Affected Locations

`modules/proxy/ajp_msg.c:503`

## Summary

`ajp_msg_get_string()` validated an AJP string’s declared length against `msg->max_size`, the allocated buffer capacity, instead of `msg->len`, the declared message boundary established by `ajp_msg_check_header()`. A peer-controlled AJP message could therefore cause string parsing to return a pointer into bytes beyond the valid message body when the string length exceeded `msg->len` but remained within `msg->max_size`.

## Provenance

Reported and reproduced from Swival Security Scanner evidence: https://swival.dev

Confidence: certain.

## Preconditions

An AJP peer sends a string field whose declared string length extends beyond the declared AJP message body while still remaining within the allocated message buffer capacity.

## Proof

`ajp_msg_check_header()` sets `msg->len` from the AJP header’s declared body length plus `AJP_HEADER_LEN`. Network bytes populate `msg->buf`, but only bytes up to `msg->len` are part of the valid message.

Before the patch, `ajp_msg_get_string()` read a 16-bit string size, saved `start = msg->pos`, and rejected only when:

```c
(status != APR_SUCCESS) || (size + start > msg->max_size)
```

This allowed `size + start` to exceed `msg->len` as long as it did not exceed `msg->max_size`. The function then advanced `msg->pos` and returned:

```c
*rvalue = (const char *)(msg->buf + start);
```

The reproduced harness used `len=8`, `max_size=32`, and a string length of `10`. The vulnerable logic returned success, advanced `pos` to `17`, and exposed bytes beyond the declared message:

```text
rc=0 pos=17 len=8 max=32 returned_offset=6 strlen=10 value_prefix='OKSSSSSSSS'
```

## Why This Is A Real Bug

`msg->len` is the authoritative boundary for parsed AJP message contents. `msg->max_size` is only the allocation capacity. Accepting a string that crosses `msg->len` lets peer-controlled metadata cause parsing of stale or uninitialized buffer bytes outside the declared message.

This is practically reachable while parsing AJP string fields from peer-controlled messages. The impact is an out-of-message read from reused or uncleared buffer contents. `ajp_msg_create()` allocates `msg->buf` with `apr_palloc()`, and `ajp_msg_reuse()` preserves the buffer without clearing it, so bytes after `msg->len` may contain leftovers from prior messages. Consumers then treat the returned pointer as a C string, including formatting and header-processing paths such as `modules/proxy/ajp_header.c:565`, which can leak stale data into parsed state or trigger over-read/crash behavior if a NUL is not encountered promptly.

## Fix Requirement

Validate AJP string size, terminator location, and position advancement against `msg->len`, not `msg->max_size`.

## Patch Rationale

The patch changes `ajp_msg_get_string()` to reject strings whose payload plus required NUL terminator would exceed the declared message boundary:

```c
(size + start >= msg->len)
```

Because AJP strings are length-prefixed and NUL-terminated, `size + start` is the terminator index. Requiring this index to be strictly less than `msg->len` ensures both the string bytes and terminator are inside the declared message.

The patch also validates the terminator byte:

```c
msg->buf[start + size] != '\0'
```

This prevents returning a pointer to data that is not a properly terminated AJP string within the declared message.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/ajp_msg.c b/modules/proxy/ajp_msg.c
index 3367b5d..7037d22 100644
--- a/modules/proxy/ajp_msg.c
+++ b/modules/proxy/ajp_msg.c
@@ -507,7 +507,8 @@ apr_status_t ajp_msg_get_string(ajp_msg_t *msg, const char **rvalue)
     status = ajp_msg_get_uint16(msg, &size);
     start = msg->pos;
 
-    if ((status != APR_SUCCESS) || (size + start > msg->max_size)) {
+    if ((status != APR_SUCCESS) || (size + start >= msg->len)
+        || (msg->buf[start + size] != '\0')) {
         return ajp_log_overflow(msg, "ajp_msg_get_string");
     }
```