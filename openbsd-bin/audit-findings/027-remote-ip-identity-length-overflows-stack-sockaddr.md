# Remote IP Identity Length Overflows Stack Sockaddr

## Classification

Memory corruption, high severity.

## Affected Locations

`sbin/iked/ikev2.c:3402`

`sbin/iked/ikev2.c:7025`

`sbin/iked/ikev2.c:7044`

## Summary

`ikev2_print_id()` derives the IP identity byte count from the attacker-controlled ID payload length and copies that count into fixed-size stack socket address fields. Oversized `ID_IPV4` or `ID_IPV6` values in IKE_AUTH can therefore overwrite stack memory before authentication succeeds.

## Provenance

Verified from supplied source, reproducer evidence, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Peer completes IKE_SA_INIT.
- Peer reaches encrypted IKE_AUTH parsing with an accepted policy.
- Peer sends an oversized `ID_IPV4` or `ID_IPV6` identity payload.

## Proof

- `ikev2_ike_auth_recv()` copies `msg->msg_peerid` into `sa_iid` or `sa_rid` during IKE_AUTH handling before authentication is complete.
- Error and logging paths call `ikev2_print_id()` through `ikev2_send_auth_failed()` and `ikev2_log_established()`.
- `ikev2_print_id()` computes `len = ibuf_size(id->id_buf) - id->id_offset`.
- For `IKEV2_ID_IPV4`, the vulnerable code copies `len` bytes into `s4.sin_addr.s_addr`, which is 4 bytes.
- For `IKEV2_ID_IPV6`, the vulnerable code copies `len` bytes into `s6.sin6_addr`, which is 16 bytes.
- The reproducer used a 128-byte `ID_IPV4` value and ASan reported `AddressSanitizer: stack-buffer-overflow` at the `memcpy` into `s4`.

## Why This Is A Real Bug

The ID parser only validates that an ID payload exists and that the ID type is not `IKEV2_ID_NONE`; it does not enforce the fixed wire sizes required for IP identities. Because `len` is controlled by the IKE_AUTH ID payload length, the copy size can exceed the destination field size. The destination fields are embedded in stack-allocated `struct sockaddr_in` and `struct sockaddr_in6`, so the overflow corrupts ikev2 process stack memory. The path is reachable by an unauthenticated peer that has reached encrypted IKE_AUTH, so the impact is remotely triggerable process memory corruption and at least denial of service.

## Fix Requirement

Reject malformed IP identity payloads before copying:

- `IKEV2_ID_IPV4` must contain exactly 4 bytes after `id_offset`.
- `IKEV2_ID_IPV6` must contain exactly 16 bytes after `id_offset`.
- Any other length must return failure without calling `memcpy()`.

## Patch Rationale

The patch adds exact-size checks immediately before the IPv4 and IPv6 `memcpy()` operations in `ikev2_print_id()`. This places validation at the sink that performs the fixed-size stack copy, covering all current callers and both failure/logging paths. Returning `-1` preserves existing caller behavior for malformed IDs.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/ikev2.c b/sbin/iked/ikev2.c
index e235542..f0d667d 100644
--- a/sbin/iked/ikev2.c
+++ b/sbin/iked/ikev2.c
@@ -7023,6 +7023,8 @@ ikev2_print_id(struct iked_id *id, char *idstr, size_t idstrlen)
 
 	switch (id->id_type) {
 	case IKEV2_ID_IPV4:
+		if ((size_t)len != sizeof(s4.sin_addr.s_addr))
+			return (-1);
 		s4.sin_family = AF_INET;
 		s4.sin_len = sizeof(s4);
 		memcpy(&s4.sin_addr.s_addr, ptr, len);
@@ -7042,6 +7044,8 @@ ikev2_print_id(struct iked_id *id, char *idstr, size_t idstrlen)
 		free(str);
 		break;
 	case IKEV2_ID_IPV6:
+		if ((size_t)len != sizeof(s6.sin6_addr))
+			return (-1);
 		s6.sin6_family = AF_INET6;
 		s6.sin6_len = sizeof(s6);
 		memcpy(&s6.sin6_addr, ptr, len);
```