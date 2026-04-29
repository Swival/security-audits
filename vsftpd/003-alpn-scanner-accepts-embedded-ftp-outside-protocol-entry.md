# ALPN scanner accepts embedded ftp outside protocol entry

## Classification

security_control_failure, high severity, confidence certain.

## Affected Locations

`ssl.c:749`

## Summary

`ssl_alpn_callback` is registered as the OpenSSL ALPN selection callback and is intended to verify FTP protocol intention. The original implementation scans the entire attacker-controlled ALPN byte buffer byte-by-byte and accepts any occurrence of `03 66 74 70`. Because ALPN is a length-prefixed protocol-name list, this accepts embedded `\x03ftp` bytes inside a non-FTP protocol entry and allows the TLS handshake to proceed.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The server is built with SSL support.
- A remote TLS client sends a crafted ALPN extension.
- The ALPN callback is active via `SSL_CTX_set_alpn_select_cb`.

## Proof

The ALPN callback initializes rejection state, then originally loops over every byte in `p_in`. It checks whether the current byte sequence is:

```text
03 66 74 70
```

A valid crafted ALPN list can be:

```text
05 78 03 66 74 70
```

This encodes one protocol entry of length `5` with payload:

```text
x\x03ftp
```

It does not contain an exact ALPN protocol entry equal to `ftp`. However, the byte-by-byte scan reaches the embedded payload byte `0x03`, matches `03 66 74 70`, sets `is_ok = 1`, sets `*p_out` to `ftp`, sets `*outlen = 3`, and returns `SSL_TLSEXT_ERR_OK` instead of `SSL_TLSEXT_ERR_ALERT_FATAL`.

## Why This Is A Real Bug

ALPN protocol names are not free-form substrings; they are length-prefixed entries. A security check that is intended to accept only the FTP protocol intention must parse entry boundaries and compare the complete protocol name. The original code ignores those boundaries, so attacker-controlled bytes inside another protocol name can satisfy the check. This is a deterministic fail-open in the TLS handshake path.

## Fix Requirement

Parse the ALPN input as a sequence of length-prefixed protocol entries and accept only an entry whose length is exactly `3` and whose bytes are exactly `ftp`. Malformed/truncated entries must not be accepted.

## Patch Rationale

The patch changes the loop from byte-wise scanning to ALPN entry parsing:

- Reads `proto_len` from the current ALPN entry length byte.
- Computes remaining bytes from the current offset.
- Stops parsing if the declared protocol length exceeds the remaining buffer.
- Accepts only `proto_len == 3` with bytes `f`, `t`, `p`.
- Advances by `proto_len + 1` to the next protocol entry.

This prevents embedded `\x03ftp` sequences inside another protocol entry from being treated as a valid FTP ALPN protocol.

## Residual Risk

None

## Patch

```diff
diff --git a/ssl.c b/ssl.c
index 6e042aa..ee3b905 100644
--- a/ssl.c
+++ b/ssl.c
@@ -744,12 +744,13 @@ ssl_alpn_callback(SSL* p_ssl,
   *p_out = p_in;
   *outlen = 0;
 
-  for (i = 0; i < inlen; ++i) {
+  for (i = 0; i < inlen;) {
+    unsigned int proto_len = p_in[i];
     unsigned int left = (inlen - i);
-    if (left < 4) {
-      continue;
+    if (proto_len + 1 > left) {
+      break;
     }
-    if (p_in[i] == 3 && p_in[i + 1] == 'f' && p_in[i + 2] == 't' &&
+    if (proto_len == 3 && p_in[i + 1] == 'f' && p_in[i + 2] == 't' &&
         p_in[i + 3] == 'p')
     {
       is_ok = 1;
@@ -757,6 +758,7 @@ ssl_alpn_callback(SSL* p_ssl,
       *outlen = 3;
       break;
     }
+    i += proto_len + 1;
   }
   
   if (!is_ok)
```