# TLS 1.3 Empty Handshake Record Indexed Without Bounds Check

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/crypto/tls/Client.zig:1239`
- `lib/std/crypto/tls/Client.zig:1254-1258`

## Summary

The TLS client post-handshake parser assumes every TLS 1.3 decrypted handshake record contains at least a 4-byte handshake header. A malicious authenticated TLS 1.3 server can send an encrypted post-handshake record whose inner content type is `handshake` but whose handshake payload is only 0 to 3 bytes. The client then indexes or slices `cleartext` without first checking its length, causing a bounds-check trap and terminating the client process.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: https://swival.dev

## Preconditions

- The client has established a TLS 1.3 session with an attacker-controlled server.
- The attacker controls the server-side TLS peer and can send authenticated TLS 1.3 application-data records carrying post-handshake content.

## Proof

After `init` returns, `readIndirect` decrypts TLS 1.3 records, trims padding, and derives:

```zig
break :cleartext .{ msg.len - 1, @enumFromInt(msg[msg.len - 1]) };
```

If the derived inner content type is `.handshake`, parsing proceeds here:

```zig
.handshake => {
    var ct_i: usize = 0;
    while (true) {
        const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
        ct_i += 1;
        const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
```

There is no check that `cleartext.len >= 4`.

Confirmed dynamic reproduction with a locally encrypted TLS 1.3 ChaCha20Poly1305 record whose decrypted plaintext contained only the inner content type byte `0x16`. This yields a zero-length handshake payload and traps:

```text
panic: index out of bounds: index 0, len 0
.../lib/std/crypto/tls/Client.zig:1257 in readIndirect
    const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
```

For 1 to 3 payload bytes, the later slice `cleartext[ct_i..][0..3]` is similarly unchecked.

## Why This Is A Real Bug

TLS 1.3 post-handshake records are encrypted and authenticated with application traffic keys. After session establishment, a malicious server has the required server application traffic key and can produce valid records accepted by the client.

Malformed post-handshake handshake data should be rejected with a TLS parse error such as `TlsBadLength` or `TlsDecodeError`. Instead, the client performs unchecked indexing on attacker-controlled plaintext length and traps, creating a remotely triggerable client denial of service by the server peer.

## Fix Requirement

Before reading the post-handshake handshake type and 24-bit length field, verify that at least 4 bytes remain in the decrypted handshake payload.

Required behavior:

- If fewer than 4 bytes remain, return a TLS read failure.
- Do not index `cleartext[ct_i]`.
- Do not slice `cleartext[ct_i..][0..3]`.

## Patch Rationale

The patch adds a single bounds check at the top of the handshake parsing loop:

```zig
if (ct_i + 4 > cleartext.len) return failRead(c, error.TlsBadLength);
```

This validates that the complete handshake header is present before reading:

- 1 byte handshake type
- 3 bytes handshake length

The existing later check remains responsible for validating the declared handshake body length:

```zig
if (next_handshake_i > cleartext.len) return failRead(c, error.TlsBadLength);
```

Together, these checks cover both truncated headers and truncated bodies.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/tls/Client.zig b/lib/std/crypto/tls/Client.zig
index 3f96531e94..7a40e68c3e 100644
--- a/lib/std/crypto/tls/Client.zig
+++ b/lib/std/crypto/tls/Client.zig
@@ -1254,6 +1254,7 @@ fn readIndirect(c: *Client) Reader.Error!usize {
         .handshake => {
             var ct_i: usize = 0;
             while (true) {
+                if (ct_i + 4 > cleartext.len) return failRead(c, error.TlsBadLength);
                 const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                 ct_i += 1;
                 const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
```