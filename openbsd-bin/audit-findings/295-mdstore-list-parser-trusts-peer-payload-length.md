# mdstore list parser trusts peer payload length

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

- `usr.sbin/ldomctl/mdstore.c:211`
- `usr.sbin/ldomctl/mdstore.c:231`
- `usr.sbin/ldomctl/mdstore.c:233`
- `usr.sbin/ldomctl/mdstore.c:237`

## Summary

`mdstore_rx_data()` parses mdstore list replies using the peer-controlled internal `payload_len` field instead of the actual received buffer length. A malicious mdstore peer can advertise a larger payload than was received, causing `xstrdup()` and `strlen()` to scan beyond the reassembled message buffer and potentially terminate `ldomctl`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `ldomctl` is connected to an attacker-controlled mdstore service.
- `ldomctl` has sent `MDSET_LIST_REQUEST`, setting `mdstore_command` to `MDSET_LIST_REQUEST`.
- The attacker can send a matching mdstore list reply with `payload_len` larger than the actual received message length.

## Proof

`mdstore_start()` sends `MDSET_LIST_REQUEST` and stores that command in `mdstore_command`.

A later peer `DS_DATA` message for the matching service handle is dispatched to:

- `usr.sbin/ldomctl/mdstore.c:211`: `struct mdstore_list_resp *mr = data;`

The parser then processes list replies under `MDSET_LIST_REQUEST`. The vulnerable loop discards the real received `len`:

```c
for (idx = 0, len = 0; len < mr->payload_len - 24; idx++) {
```

The bound `mr->payload_len - 24` is controlled by the peer. The loop body treats `&mr->sets[len]` as an in-bounds NUL-terminated string:

```c
set->name = xstrdup(&mr->sets[len]);
...
len += strlen(&mr->sets[len]) + 1;
```

If `payload_len` exceeds the actual received buffer, both `xstrdup()` and `strlen()` can read past `data`.

Existing LDC framing only limits the actual reassembled message size to `LDC_MSG_MAX`; it does not require the mdstore-internal `payload_len` to match the actual message length.

## Why This Is A Real Bug

The vulnerable code trusts a length field supplied by the mdstore peer after receiving an independently sized buffer from the transport. The actual buffer length is available as the `len` argument, but the list parser replaces it with `0` and uses `mr->payload_len` as the loop limit. Because string duplication and string length calculation require finding a NUL byte, an inflated `payload_len` can force reads outside the received message. This is attacker-triggerable denial of service of `ldomctl`.

## Fix Requirement

The parser must validate that the received buffer contains the fields it reads and must bound list iteration by the actual received buffer length. String parsing must not call unbounded string routines on peer-provided data unless a NUL byte is known to exist inside the valid buffer.

## Patch Rationale

The patch adds defensive bounds checks before reading `mr->result` and before parsing the `sets` array. It computes the usable list payload as the minimum of:

- the bytes actually present after `sets`
- the peer-advertised `payload_len - 24`

The list parser then uses `memchr()` to find a NUL terminator within the remaining bounded payload before calling `xstrdup()`. The loop advances using the bounded terminator location instead of an unbounded `strlen()` result.

This preserves normal parsing while preventing overreads when the peer advertises a payload larger than the received buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdstore.c b/usr.sbin/ldomctl/mdstore.c
index 3592fca..ad284d6 100644
--- a/usr.sbin/ldomctl/mdstore.c
+++ b/usr.sbin/ldomctl/mdstore.c
@@ -18,6 +18,7 @@
 
 #include <assert.h>
 #include <err.h>
+#include <stddef.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -210,8 +211,14 @@ mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 {
 	struct mdstore_list_resp *mr = data;
 	struct mdstore_set *set;
+	char *end;
+	size_t payload_len;
 	int idx;
 
+	if (len < offsetof(struct mdstore_list_resp, result) +
+	    sizeof(mr->result))
+		goto out;
+
 	if (mr->result != MDST_SUCCESS) {
 		switch (mr->result) {
 		case MDST_SET_EXISTS_ERR:
@@ -228,13 +235,21 @@ mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 
 	switch (mdstore_command) {
 	case MDSET_LIST_REQUEST:
-		for (idx = 0, len = 0; len < mr->payload_len - 24; idx++) {
+		if (len < offsetof(struct mdstore_list_resp, sets) ||
+		    mr->payload_len < 24)
+			break;
+		payload_len = min(len - offsetof(struct mdstore_list_resp, sets),
+		    mr->payload_len - 24);
+		for (idx = 0, len = 0; len < payload_len; idx++) {
+			end = memchr(&mr->sets[len], '\0', payload_len - len);
+			if (end == NULL)
+				break;
 			set = xmalloc(sizeof(*set));
 			set->name = xstrdup(&mr->sets[len]);
 			set->booted_set = (idx == mr->booted_set);
 			set->boot_set = (idx == mr->boot_set);
 			TAILQ_INSERT_TAIL(&mdstore_sets, set, link);
-			len += strlen(&mr->sets[len]) + 1;
+			len += end - &mr->sets[len] + 1;
 			if (mdstore_major >= 2)
 				len += sizeof(uint64_t); /* skip timestamp */
 			if (mdstore_major >= 3)
@@ -243,6 +258,7 @@ mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 		break;
 	}
 
+out:
 	mdstore_command = 0;
 }
```