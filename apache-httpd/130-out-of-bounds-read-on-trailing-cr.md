# Out-of-Bounds Read on Trailing CR

## Classification

Memory safety; CWE-125 out-of-bounds read; severity medium; confidence certain

## Affected Locations

`server/core_filters.c:185`

## Summary

`ap_core_input_filter()` scans bucket data in `AP_MODE_EATCRLF` to consume blank lines after requests. When a bucket ends with `APR_ASCII_CR` and the following `APR_ASCII_LF` is not present in the same bucket, the CRLF check reads `*(c + 1)` while `c` points at the final byte. This dereferences one byte past the buffer returned by `apr_bucket_read()`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ap_core_input_filter()` is called with `mode == AP_MODE_EATCRLF`.
- `apr_bucket_read()` returns data where the last byte is `APR_ASCII_CR`.
- The matching `APR_ASCII_LF`, if any, is not present in the same returned bucket buffer.

## Proof

`server/core_filters.c:176` reads a bucket into `str,len` using `apr_bucket_read()`.

`server/core_filters.c:181` initializes `c = str`.

The loop condition at `server/core_filters.c:182` permits `c == str + len - 1`.

At that position:

```c
else if (*c == APR_ASCII_CR && *(c + 1) == APR_ASCII_LF)
```

If `*c == APR_ASCII_CR`, the expression evaluates `*(c + 1)`, where `c + 1 == str + len`. That address is one byte past the buffer returned by `apr_bucket_read()`.

A client can produce this condition when nonblocking network input supplies a bucket ending in `\r` without a following `\n` in the same read. The reproduced trigger is the narrower `AP_MODE_EATCRLF` path.

## Why This Is A Real Bug

The loop bounds only prove that `c` is within `[str, str + len)`. They do not prove that `c + 1` is also within the returned buffer. C permits forming a one-past pointer, but dereferencing it is undefined behavior.

The fault is reachable through normal input filtering when consuming blank lines after requests. Depending on allocator layout and adjacent memory, the out-of-bounds read can crash under memory checking or incorrectly observe an adjacent byte as `APR_ASCII_LF`, causing incorrect CRLF consumption.

## Practical Exploit Scenario

A site accepts pipelined keep-alive HTTP/1.1 requests, which is normal behavior for browsers, command-line clients, and any benchmark or monitoring tool. Between requests on the same connection, Apache calls `ap_core_input_filter` in `AP_MODE_EATCRLF` to consume the blank line that often precedes a follow-up request.

An attacker scripts a client that deliberately splits the inter-request whitespace across two separate writes so the kernel delivers the trailing `\r` and the following `\n` in distinct reads:

```python
sock.sendall(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
sock.recv(4096)              ; drain first response
sock.sendall(b"\r")          ; lone CR, ends one bucket
time.sleep(0.05)
sock.sendall(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
```

The first read returns a one-byte bucket whose data ends at `\r`. `ap_core_input_filter` enters the EATCRLF loop, sees `*c == '\r'`, and immediately evaluates `*(c + 1)`. That address is one byte past the bucket buffer. Three observable outcomes follow depending on what lives there:

- On a build with ASan, FORTIFY, or pool guard pages, the read faults and the worker dies. The attacker scripts thousands of these connections per second from a single source and exhausts the MPM pool, denying service to legitimate clients.
- On a stock build where the next byte happens to equal `\n`, the filter consumes two bytes (one of which was never sent), and the next request's leading byte is silently dropped. The follow-up request is parsed as malformed, returning 400 to a perfectly valid client.
- On a stock build where the next byte does not equal `\n`, the filter returns success without consuming the `\r`. That stray CR then becomes the first byte of the next request, again producing a 400 for traffic the client built correctly.

The trigger is purely a TCP timing pattern, requires no malformed header data, and is invisible at the HTTP layer. An adversarial network actor (or any client behind an unusually slow segment) can sustain the crash variant and continuously knock workers offline.

## Fix Requirement

Before reading `*(c + 1)`, ensure that `c + 1 < str + len`.

## Patch Rationale

The patch preserves existing behavior for complete `CRLF` pairs within a bucket while treating a trailing standalone `CR` as non-consumable input. The added bound check ensures the second byte of the pair is present before it is read.

## Residual Risk

None

## Patch

```diff
diff --git a/server/core_filters.c b/server/core_filters.c
index c4ab603..42f96f7 100644
--- a/server/core_filters.c
+++ b/server/core_filters.c
@@ -182,7 +182,8 @@ apr_status_t ap_core_input_filter(ap_filter_t *f, apr_bucket_brigade *b,
             while (c < str + len) {
                 if (*c == APR_ASCII_LF)
                     c++;
-                else if (*c == APR_ASCII_CR && *(c + 1) == APR_ASCII_LF)
+                else if (*c == APR_ASCII_CR && c + 1 < str + len
+                         && *(c + 1) == APR_ASCII_LF)
                     c += 2;
                 else
                     return APR_SUCCESS;
```