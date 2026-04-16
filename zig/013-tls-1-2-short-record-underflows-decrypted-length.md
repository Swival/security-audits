# TLS 1.2 Short Record Underflows Decrypted Length

## Classification

- Type: Denial of Service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/tls/Client.zig:1207`
- Function: `readIndirect`
- Branch: post-handshake TLS 1.2 application record decryption

## Summary

A malicious TLS server can crash a Zig TLS client after a TLS 1.2 session is established by sending a post-handshake record whose length is smaller than the TLS 1.2 explicit IV plus authentication tag length.

`readIndirect` checks only that `record_len <= max_ciphertext_len`. In the TLS 1.2 branch it then computes:

```zig
const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
```

without first validating the minimum record length. For short records, this checked unsigned subtraction underflows in safe Zig builds and traps the client process instead of returning a TLS read error.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- The client has established a TLS 1.2 session.
- The connected server is attacker-controlled or can send attacker-controlled TLS records.
- The attacker sends a fully buffered post-handshake TLS record with:

```text
record_len < P.record_iv_length + P.mac_length
```

## Proof

Trigger path:

1. Client completes a TLS 1.2 handshake with an attacker-controlled server.
2. Server sends a post-handshake TLS record with a small length, for example `0` or `15`.
3. `readIndirect` parses the record header.
4. The record passes the existing maximum-length check:

   ```zig
   if (record_len > max_ciphertext_len) return failRead(c, error.TlsRecordOverflow);
   ```

5. The TLS 1.2 branch computes:

   ```zig
   const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
   ```

6. If `record_len` is less than the required overhead, unsigned subtraction underflows.
7. In Zig safe builds, the underflow causes a runtime panic/trap.
8. The client process terminates instead of returning `error.ReadFailed` with a TLS error such as `error.TlsRecordOverflow`.

The TLS 1.3 branch already performs the required minimum-length check, and the TLS 1.2 handshake decrypt path also contains such a check. The post-handshake TLS 1.2 `readIndirect` path was missing it.

## Why This Is A Real Bug

The length field is attacker-controlled after the TLS session is established. A malicious server can provide a syntactically complete TLS record whose declared length is below the minimum required for TLS 1.2 AEAD records.

Because the subtraction happens before any minimum-length validation, malformed network input can trigger arithmetic underflow. This is not merely a decryption failure: execution traps before the code can return a controlled TLS read error. That makes the issue an attacker-triggerable denial of service against the client process.

## Fix Requirement

Before subtracting TLS 1.2 record overhead from `record_len`, validate:

```zig
record_len >= P.record_iv_length + P.mac_length
```

If the record is too short, return a TLS read failure using the existing error path:

```zig
return failRead(c, error.TlsRecordOverflow);
```

## Patch Rationale

The patch adds the same class of minimum-length guard already present in the TLS 1.3 read path and TLS 1.2 handshake decrypt path.

This prevents unsigned subtraction underflow and preserves the intended behavior: malformed records are reported as TLS read errors instead of crashing the process.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/tls/Client.zig b/lib/std/crypto/tls/Client.zig
index 3f96531e94..8f57368ce6 100644
--- a/lib/std/crypto/tls/Client.zig
+++ b/lib/std/crypto/tls/Client.zig
@@ -1202,6 +1202,7 @@ fn readIndirect(c: *Client) Reader.Error!usize {
             .tls_1_2 => {
                 const pv = &p.tls_1_2;
                 const P = @TypeOf(p.*);
+                if (record_len < P.record_iv_length + P.mac_length) return failRead(c, error.TlsRecordOverflow);
                 const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                 const ad_header = input.take(tls.record_header_len) catch unreachable; // already peeked
                 const ad = mem.toBytes(big(c.read_seq)) ++
```