# Huffman Literal Name Uses Attacker-Sized `alloca`

## Classification

- Finding type: Denial of service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/http3/qpack.c:378`
- Function: `insert_without_name_reference`
- Caller path: `h2o_qpack_decoder_handle_input` → `insert_without_name_reference`

## Summary

A malicious HTTP/3 peer can send a QPACK encoder-stream `insert without name reference` instruction with the Huffman-name bit set and a large attacker-controlled encoded name length. The decoder uses that length directly in `alloca(qnlen * 2)`, allowing stack exhaustion before dynamic table size rejection occurs.

## Provenance

Verified and patched from a reproduced Swival security finding.

- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- Peer can send QPACK encoder stream instructions.

## Proof

The vulnerable path is:

```c
case 2:
case 3: /* insert without name reference */ {
    int64_t name_len, value_len;
    int name_is_huff = (*src & 0x20) != 0;
    ...
    ret = insert_without_name_reference(qpack, name_is_huff, name, name_len, value_is_huff, src, value_len, err_desc);
}
```

`name_len` is read from attacker-controlled encoder-stream input. The parser only verifies that the encoded name bytes are present in the input buffer.

The callee then performs:

```c
if (qnhuff) {
    name.base = alloca(qnlen * 2);
    if ((name.len = h2o_hpack_decode_huffman(name.base, &soft_errors, qn, qnlen, 1, err_desc)) == SIZE_MAX)
        return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
}
```

In-process reproducer result:

- Instruction: insert-without-name-reference with Huffman-name bit set
- Encoded name length: `5,000,000`
- Attempted stack allocation: `10,000,000`
- Result: ASAN `stack-overflow` in `h2o_qpack_decoder_handle_input` before the function returned

Follow-up testing with a local HTTP/3 client against a local ASAN `h2o` server confirmed network reachability of the vulnerable path, but did not produce a server crash with the largest complete instruction accepted by the default flow-control window:

```text
client: sent 036 encoder payload len=417005 name_len=417000
h3-repro-server: qpack encoder stream input bytes=417005 eos=0
h3-repro-server: insert_without_name_reference qnlen=417000 alloca=834000
```

A larger HTTP/3 payload (`name_len=5,000,000`) did not reach `insert_without_name_reference`; the server stopped receiving the QPACK encoder stream at approximately `417807` bytes. This matches the default server-side HTTP/3 unidirectional stream receive window derived from:

- `H2O_MAX_REQLEN = 8192 + 4096 * 100 = 417792`
- `h2o_http3_calc_min_flow_control_size` adds 16 bytes
- Effective size: approximately `417808` bytes

Therefore, with the stock local server configuration, this issue is confirmed reachable over HTTP/3 as an attacker-controlled `alloca`, while reproducing an actual network-triggered crash depends on the connection/thread stack size and the receive window available to the QPACK encoder stream.

## Why This Is A Real Bug

The allocation size is directly controlled by the peer-provided Huffman encoded name length. The stack allocation occurs before the decoded header name is checked against table capacity by later insertion logic. Therefore, normal QPACK table-size rejection does not protect this path.

A single validly framed encoder-stream instruction can force an attacker-sized stack allocation in the HTTP/3 connection handling path. In local HTTP/3 server testing, the default QPACK encoder-stream receive window limited the largest complete instruction to about 417 KB of encoded name data, which reached `alloca(834000)` but did not crash that particular server process. Larger allocations crash in the in-process reproducer, and would be reachable over HTTP/3 if the QPACK encoder-stream receive window and connection thread stack characteristics permit them.

## Fix Requirement

The decoder must not perform stack allocation based on peer-controlled QPACK literal name length. Huffman literal name decoding must either:

- allocate from heap with overflow and allocation-failure checks, or
- reject Huffman name lengths above a fixed safe limit before allocation.

## Patch Rationale

The patch replaces attacker-sized `alloca(qnlen * 2)` with checked heap allocation:

```c
if (qnlen > (SIZE_MAX - 1) / 2 || (name_buf = malloc((size_t)qnlen * 2 + 1)) == NULL) {
    *err_desc = h2o_qpack_err_header_name_too_long;
    return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
}
```

This removes stack exhaustion risk, handles integer overflow, and returns a QPACK decompression failure if allocation cannot be performed.

The temporary heap buffer is freed on Huffman decode failure and after the token/literal insertion decision completes.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/http3/qpack.c b/lib/http3/qpack.c
index 1750aa188..8ed0e0af5 100644
--- a/lib/http3/qpack.c
+++ b/lib/http3/qpack.c
@@ -369,12 +369,19 @@ static int insert_without_name_reference(h2o_qpack_decoder_t *qpack, int qnhuff,
                                          const uint8_t *qv, int64_t qvlen, const char **err_desc)
 {
     h2o_iovec_t name;
+    char *name_buf = NULL;
     unsigned soft_errors = 0;
 
     if (qnhuff) {
-        name.base = alloca(qnlen * 2);
-        if ((name.len = h2o_hpack_decode_huffman(name.base, &soft_errors, qn, qnlen, 1, err_desc)) == SIZE_MAX)
+        if (qnlen > (SIZE_MAX - 1) / 2 || (name_buf = malloc((size_t)qnlen * 2 + 1)) == NULL) {
+            *err_desc = h2o_qpack_err_header_name_too_long;
             return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
+        }
+        name.base = name_buf;
+        if ((name.len = h2o_hpack_decode_huffman(name.base, &soft_errors, qn, qnlen, 1, err_desc)) == SIZE_MAX) {
+            free(name_buf);
+            return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
+        }
     } else {
         if (!h2o_hpack_validate_header_name(&soft_errors, (void *)qn, qnlen, err_desc))
             return H2O_HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED;
@@ -382,11 +389,14 @@ static int insert_without_name_reference(h2o_qpack_decoder_t *qpack, int qnhuff,
     }
 
     const h2o_token_t *token;
+    int ret;
     if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
-        return insert_token_header(qpack, token, qvhuff, qv, qvlen, err_desc);
+        ret = insert_token_header(qpack, token, qvhuff, qv, qvlen, err_desc);
     } else {
-        return insert_literal_header(qpack, name.base, name.len, qvhuff, qv, qvlen, soft_errors, err_desc);
+        ret = insert_literal_header(qpack, name.base, name.len, qvhuff, qv, qvlen, soft_errors, err_desc);
     }
+    free(name_buf);
+    return ret;
 }
 
 static int duplicate(h2o_qpack_decoder_t *qpack, int64_t index, const char **err_desc)
```