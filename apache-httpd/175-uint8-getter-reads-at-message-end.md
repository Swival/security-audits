# uint8 getter reads at message end

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/proxy/ajp_msg.c:478`

## Summary

`ajp_msg_get_uint8()` permits `msg->pos == msg->len` and then reads `msg->buf[msg->pos++]`. Since `msg->len` is the declared end of the current AJP message, this reads one byte past the message boundary. A backend-controlled malformed AJP packet can trigger the condition during normal response parsing.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`ajp_msg_get_uint8()` is called when `msg->pos` equals `msg->len`.

## Proof

The vulnerable helper only rejects positions strictly greater than the message length:

```c
if (msg->pos > msg->len) {
    return ajp_log_overflow(msg, "ajp_msg_get_uint8");
}

*rvalue = msg->buf[msg->pos++];
```

A reproduced backend response sequence reaches this state:

1. Backend sends a valid zero-length body chunk to seed `msg->buf[4]` with `CMD_AJP13_SEND_BODY_CHUNK`:
   `41 42 00 04 03 00 00 00`
2. `ajp_parse_data()` succeeds; because it is a zero-length flush before headers, `mod_proxy_ajp.c:524` logs/ignores it and continues.
3. Backend sends a malformed zero-body AJP packet:
   `41 42 00 00`
4. `ajp_read_header()` reuses the same buffer, sets `pos == len == 4`, and reads no body.
5. Vulnerable `peek_uint8` reads stale `buf[4] == 0x03`, causing dispatch to `CMD_AJP13_SEND_BODY_CHUNK`.
6. `modules/proxy/ajp_header.c:811` calls `ajp_msg_get_uint8()` with `pos == len`, causing the out-of-message read in `modules/proxy/ajp_msg.c`.

## Why This Is A Real Bug

`msg->len` is set from the AJP packet header by `ajp_msg_check_header()` and represents the first byte after the declared message. A one-byte getter must require at least one remaining byte, so `pos == len` is already out of bounds for the current message. The reproduced path shows the read can consume stale data from a reused buffer and influence parser dispatch before later overflow handling occurs.

## Fix Requirement

Reject `msg->pos >= msg->len` before reading one byte in `ajp_msg_get_uint8()`.

## Patch Rationale

Changing the guard from `>` to `>=` enforces the invariant that a one-byte read is valid only when `msg->pos` points to an existing byte inside the declared message. This prevents `ajp_msg_get_uint8()` from consuming bytes at the message end while preserving normal reads where `msg->pos < msg->len`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/ajp_msg.c b/modules/proxy/ajp_msg.c
index 3367b5d..c8ba8da 100644
--- a/modules/proxy/ajp_msg.c
+++ b/modules/proxy/ajp_msg.c
@@ -482,7 +482,7 @@ apr_status_t ajp_msg_peek_uint8(ajp_msg_t *msg, apr_byte_t *rvalue)
 apr_status_t ajp_msg_get_uint8(ajp_msg_t *msg, apr_byte_t *rvalue)
 {
 
-    if (msg->pos > msg->len) {
+    if (msg->pos >= msg->len) {
         return ajp_log_overflow(msg, "ajp_msg_get_uint8");
     }
```