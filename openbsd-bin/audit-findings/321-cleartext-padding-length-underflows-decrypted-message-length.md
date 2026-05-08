# cleartext padding length underflows decrypted message length

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`usr.sbin/sasyncd/net.c:736`

## Summary

`net_read()` trusts the peer-controlled cleartext `padlen` field and subtracts it from the decrypted message length without first checking that `padlen <= *msglen`. A configured peer that knows the shared key can send a packet where `padlen` is larger than the encrypted payload length, causing unsigned `*msglen` underflow. The resulting oversized length is passed to `SHA1_Update()`, which reads far beyond the heap allocation and can terminate `sasyncd`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- Attacker is an accepted configured `sasyncd` peer.
- Attacker knows the configured shared key.
- Attacker can send a crafted TCP message to the target `sasyncd` instance.

## Proof

Reachability is confirmed through the normal peer path:

- `net_accept()` accepts a peer by configured source address.
- `net_handle_messages()` passes the accepted peer socket to `net_read()` at `usr.sbin/sasyncd/net.c:533`.
- `net_read()` reads a peer-controlled `blob_len`, derives `*msglen`, and accepts a 60-byte blob that yields `*msglen = 16`.
- A crafted message with `msgtype = 0`, `padlen = 17`, any 20-byte hash, any 16-byte IV, and 16 bytes of ciphertext passes the existing length and type checks.
- `net_read()` decrypts exactly 16 bytes into `msg`.
- `*msglen -= padlen` underflows from `16 - 17` to `0xffffffff`.
- `SHA1_Update(&ctx, msg, *msglen)` then hashes from a 16-byte heap allocation using an approximately 4GiB length before the hash comparison can reject the packet.

## Why This Is A Real Bug

The packet is rejected only after `SHA1_Update()` computes the digest. Because `*msglen` has already underflowed, the digest operation reads outside the allocated decrypted-message buffer. This is a concrete out-of-bounds heap read on the authenticated peer input path, with practical daemon denial-of-service impact.

The existing checks do not prevent it:

- `blob_len` minimum only ensures space for the hash, IV, type, padding length, and ciphertext.
- `MSG_MINLEN` / `MSG_MAXLEN` validate the encrypted payload length before padding removal.
- `MSG_MAXTYPE` validates only the message type.
- No check ensures the cleartext `padlen` is bounded by the decrypted payload length before subtraction.

## Fix Requirement

Reject messages where `padlen > *msglen` before subtracting padding and before hashing the decrypted message.

## Patch Rationale

The patch adds the missing bounds check immediately after parsing `padlen`, before `msg` allocation, decryption, length subtraction, or hashing. This prevents unsigned underflow and avoids using an attacker-inflated length in `SHA1_Update()`.

Rejecting the packet at this point is safe because a valid sender cannot produce a padding length larger than the encrypted payload length.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/sasyncd/net.c b/usr.sbin/sasyncd/net.c
index 2d49190..0d4d26c 100644
--- a/usr.sbin/sasyncd/net.c
+++ b/usr.sbin/sasyncd/net.c
@@ -720,6 +720,10 @@ net_read(struct syncpeer *p, u_int32_t *msgtype, u_int32_t *msglen)
 	memcpy(&v, blob + offset, sizeof v);
 	padlen = ntohl(v);
 	offset += sizeof v;
+	if (padlen > *msglen) {
+		free(blob);
+		return NULL;
+	}
 
 	rhash = blob + offset;
 	iv    = rhash + sizeof hash;
```