# Header Length Check Omits Header Bytes

## Classification

Memory safety, high severity.

Confidence: certain.

## Affected Locations

- `modules/proxy/ajp_msg.c:157`
- `modules/proxy/ajp_msg.c:169`
- `modules/proxy/ajp_msg.c:177`
- `modules/proxy/ajp_link.c:98`
- `modules/proxy/ajp_header.c:838`

## Summary

`ajp_msg_check_header()` validates the AJP payload length against the full buffer size but later adds `AJP_HEADER_LEN` to compute `msg->len`. If the declared payload length is within four bytes of `msg->max_size`, the computed total message length exceeds the allocation.

This allows a malicious or compromised AJP peer to cause out-of-bounds writes during receive and later out-of-bounds reads through parsers that trust `msg->len`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- Incoming AJP header declares a valid AJP signature.
- Declared AJP payload length is `<= msg->max_size`.
- Declared AJP payload length is `> msg->max_size - AJP_HEADER_LEN`.
- Default concrete case: `max_size == 8192`, declared payload length is `0x2000`.

## Proof

`ajp_msg_check_header()` parses the payload length from bytes `head[2]` and `head[3]`:

```c
msglen  = ((head[2] & 0xff) << 8);
msglen += (head[3] & 0xFF);
```

The vulnerable check rejects only payload lengths greater than the full allocation:

```c
if (msglen > msg->max_size) {
```

A payload length equal to `msg->max_size` is accepted. The function then computes total message length by adding the AJP header:

```c
msg->len = msglen + AJP_HEADER_LEN;
```

With `max_size == 8192`, an attacker can send:

```text
41 42 20 00
```

followed by 8192 body bytes. The header declares payload length `0x2000`, which is accepted by the original check. The receive path then reads 8192 bytes into `msg->buf + 4`, writing offsets `4..8195` into a buffer allocated for offsets `0..8191`, overflowing by four bytes.

## Why This Is A Real Bug

The allocation size is `msg->max_size`, but the protocol frame stored in that allocation consists of both:

- `AJP_HEADER_LEN` bytes of header
- `msglen` bytes of declared payload

Therefore the safe invariant is:

```text
msglen + AJP_HEADER_LEN <= msg->max_size
```

The original code enforces only:

```text
msglen <= msg->max_size
```

This is insufficient and permits `msg->len` to exceed the backing buffer. The reproduced path shows an actual out-of-bounds write in `ajp_link.c` when the body is read into `msg->buf + hlen`. Later parsing can also use the inflated `msg->len`, including `ajp_parse_data` in `modules/proxy/ajp_header.c`, creating out-of-bounds read exposure through the response path.

## Fix Requirement

Reject any declared AJP payload length that cannot fit in the message buffer after reserving space for the AJP header.

Required validation:

```c
msglen <= msg->max_size - AJP_HEADER_LEN
```

before assigning:

```c
msg->len = msglen + AJP_HEADER_LEN;
```

## Patch Rationale

The patch changes the size check from comparing the declared payload length against the whole buffer to comparing it against the remaining buffer capacity after the fixed AJP header.

This preserves valid frames whose total header-plus-payload size fits in `msg->max_size`, while rejecting frames that would make `msg->len` point beyond the allocation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/ajp_msg.c b/modules/proxy/ajp_msg.c
index 3367b5d..424f710 100644
--- a/modules/proxy/ajp_msg.c
+++ b/modules/proxy/ajp_msg.c
@@ -166,7 +166,7 @@ apr_status_t ajp_msg_check_header(ajp_msg_t *msg, apr_size_t *len)
     msglen  = ((head[2] & 0xff) << 8);
     msglen += (head[3] & 0xFF);
 
-    if (msglen > msg->max_size) {
+    if (msglen > msg->max_size - AJP_HEADER_LEN) {
         ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(01081)
                      "ajp_msg_check_header() incoming message is "
                      "too big %" APR_SIZE_T_FMT ", max is %" APR_SIZE_T_FMT,
```