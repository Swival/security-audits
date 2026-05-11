# Duplicate Chunked Stops Transfer Coding Parsing

## Classification

Parser strictness / security_control_failure. Severity: medium. Confidence: certain.

## Affected Locations

`lib/content_encoding.c:768` (`Curl_build_unencoding_stack` duplicate-`chunked` early return)

## Summary

`Curl_build_unencoding_stack()` accepts an invalid HTTP `Transfer-Encoding` sequence when a duplicate `chunked` token appears before additional transfer codings.

For `Transfer-Encoding: chunked, chunked, gzip`, the second `chunked` hits the duplicate-handling branch and returns `CURLE_OK` immediately. That exits parsing before `gzip` is evaluated, bypassing the intended enforcement that no transfer coding may appear after `chunked`.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- `is_transfer` is true.
- HTTP transfer decoding is enabled.
- An attacker-controlled HTTP response can supply a `Transfer-Encoding` header containing duplicate `chunked` followed by another transfer coding.

## Proof

The HTTP response path passes the remote `Transfer-Encoding` header value to:

```c
Curl_build_unencoding_stack(data, v, TRUE)
```

For this header:

```http
Transfer-Encoding: chunked, chunked, gzip
```

the parser behavior is deterministic:

- The first `chunked` adds the chunked writer.
- The second `chunked` resolves to the same chunked writer type.
- `Curl_cwriter_get_by_type(data, cwt)` is true for the duplicate.
- The duplicate branch logs that it is ignoring duplicate `chunked`.
- Before the patch, that branch returned `CURLE_OK`.
- Parsing stopped before the trailing `gzip` token.
- The later check rejecting transfer codings after `chunked` was never reached.
- The caller only checks the returned `CURLcode`, receives `CURLE_OK`, and accepts the invalid transfer-coding sequence.

Relevant vulnerable branch:

```c
if(cwt && is_chunked && Curl_cwriter_get_by_type(data, cwt)) {
  CURL_TRC_WRITE(data, "ignoring duplicate 'chunked' decoder");
  return CURLE_OK;
}
```

## Why This Is A Real Bug

`Curl_build_unencoding_stack()` is the enforcement point for HTTP transfer-coding ordering. It contains an explicit rejection path for codings listed after `chunked`, but the duplicate-`chunked` early return prevents that check from running.

The bug is not a cosmetic parsing discrepancy: an attacker-controlled header that should be rejected is accepted with `CURLE_OK`. This is a fail-open security-control failure in HTTP `Transfer-Encoding` validation.

## Fix Requirement

Duplicate `chunked` must be ignored without terminating parsing of the remaining comma-separated transfer-coding list.

The parser must continue to evaluate later tokens so that any transfer coding after `chunked` is rejected by the existing `chunked`-not-last enforcement.

## Patch Rationale

The patch changes the duplicate-`chunked` branch from `return CURLE_OK` to `continue`.

This preserves the intended behavior of ignoring duplicate `chunked`, while ensuring parsing proceeds to subsequent transfer codings. For `chunked, chunked, gzip`, the duplicate is skipped and `gzip` is then evaluated, causing the existing rejection logic to return `CURLE_BAD_CONTENT_ENCODING`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/content_encoding.c b/lib/content_encoding.c
index 0224a8bfe9..c713817b3d 100644
--- a/lib/content_encoding.c
+++ b/lib/content_encoding.c
@@ -765,7 +765,7 @@ CURLcode Curl_build_unencoding_stack(struct Curl_easy *data,
          *  once to a message body."
          */
         CURL_TRC_WRITE(data, "ignoring duplicate 'chunked' decoder");
-        return CURLE_OK;
+        continue;
       }
 
       if(is_transfer && !is_chunked &&
```