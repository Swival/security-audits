# Short Resolver Info Message Overreads Imsg Payload

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/unwindctl/unwindctl.c:259`

## Summary

`unwindctl status` accepts resolver status messages from the configured control socket and copies resolver info payloads without validating their length. If the peer sends `IMSG_CTL_RESOLVER_INFO` with a payload shorter than `sizeof(struct ctl_resolver_info)`, `show_status_msg()` reads past the received imsg payload. With a zero-length payload, this reaches `memcpy()` with `imsg->data == NULL` and crashes `unwindctl`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- User runs `unwindctl` with `-s` pointing to an attacker-controlled UNIX control socket.
- The attacker-controlled peer responds to the `status` request with a malformed `IMSG_CTL_RESOLVER_INFO`.
- The malformed imsg has `hdr.len` smaller than `IMSG_HEADER_SIZE + sizeof(struct ctl_resolver_info)`.

## Proof

`unwindctl` accepts an arbitrary socket path through `-s` and connects to it before issuing the requested command. For `status`, it sends `IMSG_CTL_STATUS` and then processes messages from the peer.

The imsg layer accepts messages whose length is exactly `IMSG_HEADER_SIZE`; it rejects only lengths below the header size or above the maximum. After extraction:

- A zero-payload imsg leaves `imsg.data = NULL`.
- A short nonzero payload leaves `imsg.data` pointing to only the available payload bytes.

`show_status_msg()` then handles `IMSG_CTL_RESOLVER_INFO` and executes:

```c
memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
```

without checking `imsg->hdr.len`.

A malicious peer can therefore send only the imsg header with type `IMSG_CTL_RESOLVER_INFO` and `len = IMSG_HEADER_SIZE`. This reaches `memcpy(&info[0], NULL, sizeof(struct ctl_resolver_info))`, causing a practical crash. A one-byte payload instead causes a heap overread past the imsg payload allocation.

## Why This Is A Real Bug

The code trusts a peer-controlled message length but copies a fixed-size structure from `imsg->data`. The imsg framework permits zero-length and short payloads for valid headers, so the malformed message is not rejected before `show_status_msg()`. Because `unwindctl -s` can connect to an attacker-controlled socket, the attacker controls the malformed imsg and can trigger the invalid read in the client process.

## Fix Requirement

Reject `IMSG_CTL_RESOLVER_INFO` messages unless the payload length is exactly `sizeof(struct ctl_resolver_info)`, i.e. unless `imsg->hdr.len == IMSG_HEADER_SIZE + sizeof(info[0])`.

## Patch Rationale

The patch validates the full imsg length before copying the resolver info payload. This ensures `imsg->data` contains exactly the number of bytes required by `memcpy()`. Malformed short messages are rejected before dereferencing or overreading the payload buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/unwindctl/unwindctl.c b/usr.sbin/unwindctl/unwindctl.c
index 2735c33..8477b47 100644
--- a/usr.sbin/unwindctl/unwindctl.c
+++ b/usr.sbin/unwindctl/unwindctl.c
@@ -257,6 +257,8 @@ show_status_msg(struct imsg *imsg)
 
 	switch (imsg->hdr.type) {
 	case IMSG_CTL_RESOLVER_INFO:
+		if (imsg->hdr.len != IMSG_HEADER_SIZE + sizeof(info[0]))
+			errx(1, "wrong imsg len");
 		memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
 		break;
 	case IMSG_CTL_END:
```