# short DISCONNECT imsg causes out-of-bounds read

## Classification

out-of-bounds read

Severity: medium

Confidence: certain

## Affected Locations

`usr.sbin/npppd/npppd/control.c:325`

## Summary

`control_dispatch_imsg()` handles `IMSG_CTL_DISCONNECT` by casting `imsg.data` to `struct npppd_disconnect_request *` and reading `req->ppp_id` and `req->count` without first verifying that the imsg payload contains a complete request structure.

A malformed local control-socket message with a short or empty payload can therefore trigger an invalid read in the npppd control daemon, including a NULL dereference for zero-length payloads and out-of-bounds reads for partial payloads.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided verified finding and reproducer evidence.

## Preconditions

An attacker can connect to an unrestricted npppd control socket.

## Proof

`control_dispatch_imsg()` receives client imsgs with `imsg_get()` and dispatches on `imsg.hdr.type`.

For `IMSG_CTL_DISCONNECT`, the vulnerable code does:

```c
req = (struct npppd_disconnect_request *)imsg.data;
retval = npppd_ctl_disconnect(c->ctx, req->ppp_id, req->count);
```

No check confirms that:

```c
imsg.hdr.len == IMSG_HEADER_SIZE + sizeof(struct npppd_disconnect_request)
```

Reproduced behavior:

- `lib/libutil/imsg.c:444` accepts an imsg whose length is exactly `IMSG_HEADER_SIZE`.
- `imsgbuf_get()` sets `imsg.data = NULL` when there is no payload.
- `usr.sbin/npppd/npppd/control.c:324` casts `imsg.data` to `struct npppd_disconnect_request *`.
- `usr.sbin/npppd/npppd/control.c:325` reads `req->count` without validating payload length.
- With zero payload, this dereferences NULL.
- With 1-3 payload bytes, this reads past the imsg payload.
- With a 4-byte payload containing `count = 1` but no `ppp_id[]`, execution reaches `npppd_ctl_disconnect()`, which reads `ppp_id[0]` at `usr.sbin/npppd/npppd/npppd_ctl.c:184` past the supplied payload.

Impact: a malformed attacker-controlled control imsg can crash the npppd process, causing a practical local denial of service.

## Why This Is A Real Bug

The imsg layer permits messages with valid headers but short payloads. The dispatch code assumes that any `IMSG_CTL_DISCONNECT` message contains a full `struct npppd_disconnect_request`.

That assumption is false: a local client can send the correct imsg type with an empty or truncated payload. The code then performs field reads through a pointer derived from attacker-controlled message length, causing invalid memory access before any semantic validation occurs.

## Fix Requirement

Before dereferencing `imsg.data` as `struct npppd_disconnect_request`, validate that the imsg payload contains at least the fixed header, and that the variable-length `ppp_id` array is fully contained within the payload.

Malformed `IMSG_CTL_DISCONNECT` messages must be rejected without reading request fields or passing attacker-controlled short data to `npppd_ctl_disconnect()`.

## Patch Rationale

The patch adds a minimum-size check for the fixed `count` field, then validates that `count` is non-negative and that the payload contains exactly `count` entries in the `ppp_id[]` flexible array:

```c
if (imsg.hdr.len < IMSG_HEADER_SIZE + sizeof(*req)) {
	imsg_compose(&c->iev.ibuf, IMSG_CTL_FAIL, 0, 0,
	    -1, NULL, 0);
	break;
}
req = (struct npppd_disconnect_request *)imsg.data;
if (req->count < 0 ||
    imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(*req) +
    req->count * sizeof(u_int)) {
	imsg_compose(&c->iev.ibuf, IMSG_CTL_FAIL, 0, 0,
	    -1, NULL, 0);
	break;
}
```

This ensures that both the fixed header and the variable-length `ppp_id` array are fully contained within the received payload before `npppd_ctl_disconnect()` iterates over `req->ppp_id[0..count-1]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/control.c b/usr.sbin/npppd/npppd/control.c
index 61d8a9d..80b74d7 100644
--- a/usr.sbin/npppd/npppd/control.c
+++ b/usr.sbin/npppd/npppd/control.c
@@ -321,6 +321,17 @@ control_dispatch_imsg(int fd, short event, void *arg)
 			struct npppd_disconnect_request  *req;
 			struct npppd_disconnect_response  res;
 
+			if (imsg.hdr.len < IMSG_HEADER_SIZE + sizeof(*req)) {
+				imsg_compose(&c->iev.ibuf, IMSG_CTL_FAIL, 0, 0,
+				    -1, NULL, 0);
+				break;
+			}
+			req = (struct npppd_disconnect_request *)imsg.data;
+			if (req->count < 0 ||
+			    imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(*req) +
+			    req->count * sizeof(u_int)) {
+				imsg_compose(&c->iev.ibuf, IMSG_CTL_FAIL, 0, 0,
+				    -1, NULL, 0);
+				break;
+			}
-			req = (struct npppd_disconnect_request *)imsg.data;
 			retval = npppd_ctl_disconnect(c->ctx,
 			    req->ppp_id, req->count);
```