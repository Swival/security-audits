# Compressed SSH Packet Inflates Without Size Limit

## Classification

Denial of service, high severity, confirmed.

## Affected Locations

`usr.bin/ssh/packet.c:859`

## Summary

An authenticated SSH peer can negotiate delayed compression, then send a compressed post-authentication packet whose compressed length is within `PACKET_MAX_SIZE` but whose decompressed payload exceeds the intended SSH packet size bound. The receive path checked only the encrypted/compressed packet length before decompression, allowing zlib output to grow into `compression_buffer` up to the generic `sshbuf` cap and then be copied back into `incoming_packet`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Delayed compression is negotiated.
- Compression is enabled after authentication via `COMP_DELAYED`.
- The attacker is an authenticated SSH peer.
- The attacker can send a post-authentication compressed SSH packet.

## Proof

`ssh_packet_enable_delayed_compress()` enables delayed compression after authentication. In `ssh_packet_read_poll2()`, `PACKET_MAX_SIZE` is enforced on `state->packlen` before decrypting and decompressing the packet.

After decrypting, removing padding, and entering the compression path, `ssh_packet_read_poll2()` calls:

```c
uncompress_buffer(ssh, state->incoming_packet, state->compression_buffer)
```

Before the patch, `uncompress_buffer()` repeatedly appended inflated 4096-byte chunks with `sshbuf_put()` and did not verify that the decompressed payload remained within `PACKET_MAX_SIZE`.

A practical trigger is an authenticated peer negotiating `zlib@openssh.com` and sending a post-authentication compressed `SSH2_MSG_IGNORE` payload made mostly of zeros. The compressed packet remains below 256 KiB, but the inflated payload can grow far beyond the SSH packet size invariant. Although `sshbuf` has a generic 128 MiB cap, the inflated data can reach that cap and then be copied from `compression_buffer` back into `incoming_packet` via `sshbuf_putb()`, causing additional large allocation before packet dispatch.

## Why This Is A Real Bug

The protocol receive path establishes `PACKET_MAX_SIZE` as the maximum acceptable SSH packet size, but that invariant was only applied to the compressed packet length. Compression changes payload size after the length check, so accepting unbounded decompressed output permits an authenticated remote peer to force large memory allocations using a small network packet. The generic `sshbuf` maximum limits absolute growth but does not prevent the denial of service.

## Fix Requirement

Decompression must enforce the same maximum packet size invariant as the pre-decrypt packet length path. Inflation must abort before appending output that would make the decompressed payload exceed `PACKET_MAX_SIZE`.

## Patch Rationale

The patch adds a decompressed-size check inside `uncompress_buffer()` before each append to the output buffer:

```c
len = sizeof(buf) -
    ssh->state->compression_in_stream.avail_out;
if (sshbuf_len(out) > PACKET_MAX_SIZE - len)
    return SSH_ERR_INVALID_FORMAT;
if ((r = sshbuf_put(out, buf, len)) != 0)
    return r;
```

This bounds cumulative decompressed output, prevents overflow-prone addition by using `PACKET_MAX_SIZE - len`, and returns a packet-format error before `sshbuf_put()` can allocate beyond the allowed packet size.

## Residual Risk

None

## Patch

`108-compressed-ssh-packet-inflates-without-size-limit.patch`

```diff
diff --git a/usr.bin/ssh/packet.c b/usr.bin/ssh/packet.c
index 4a3a9ca..2d3de74 100644
--- a/usr.bin/ssh/packet.c
+++ b/usr.bin/ssh/packet.c
@@ -873,6 +873,7 @@ static int
 uncompress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
 {
 	u_char buf[4096];
+	size_t len;
 	int r, status;
 
 	if (ssh->state->compression_in_started != 1)
@@ -892,8 +893,11 @@ uncompress_buffer(struct ssh *ssh, struct sshbuf *in, struct sshbuf *out)
 		    Z_SYNC_FLUSH);
 		switch (status) {
 		case Z_OK:
-			if ((r = sshbuf_put(out, buf, sizeof(buf) -
-			    ssh->state->compression_in_stream.avail_out)) != 0)
+			len = sizeof(buf) -
+			    ssh->state->compression_in_stream.avail_out;
+			if (sshbuf_len(out) > PACKET_MAX_SIZE - len)
+				return SSH_ERR_INVALID_FORMAT;
+			if ((r = sshbuf_put(out, buf, len)) != 0)
 				return r;
 			break;
 		case Z_BUF_ERROR:
```