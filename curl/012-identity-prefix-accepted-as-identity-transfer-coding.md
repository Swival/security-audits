# Identity Prefix Accepted As Identity Transfer Coding

## Classification

Parser strictness / security_control_failure. Severity: low. Confidence: certain.

## Affected Locations

- `lib/content_encoding.c:735` (`Curl_build_unencoding_stack` identity prefix check inside the unsolicited-rejection branch)

## Summary

`Curl_build_unencoding_stack` accepted any transfer-coding token beginning with `identity` as the exact `identity` coding when transfer decoding was disabled and transfer-encoding skip was not enabled. This made invalid unsolicited transfer codings such as `identityXYZ` fail open instead of returning `CURLE_BAD_CONTENT_ENCODING`.

## Provenance

- Verified by reproduced finding supplied in this report.
- Scanner provenance: Swival.dev Security Scanner, https://swival.dev

## Preconditions

- HTTP transfer decoding is disabled.
- Transfer-encoding skip is not enabled.
- Parser is processing a `Transfer-Encoding` header.
- Attacker controls or influences the transfer-coding token, e.g. a remote HTTP server response.

## Proof

`Curl_build_unencoding_stack` enters the unsolicited transfer-coding rejection path when:

- `is_transfer` is true.
- `data->set.http_transfer_encoding` is false.
- The token is not exact `chunked`.

In that path, the affected code computed:

```c
bool is_identity = curl_strnequal(name, "identity", 8);
```

`curl_strnequal(name, "identity", 8)` only compares the first 8 bytes. Therefore a longer token such as `identityXYZ` evaluates true.

The subsequent rejection control treats `is_identity` as exempt:

```c
else if(is_identity)
  continue;
else
  failf(data, "Unsolicited Transfer-Encoding (%.*s) found",
        (int)namelen, name);
return CURLE_BAD_CONTENT_ENCODING;
```

As a result, `Transfer-Encoding: identityXYZ` is accepted as if it were exact `identity`, and `Curl_build_unencoding_stack` returns `CURLE_OK` instead of `CURLE_BAD_CONTENT_ENCODING`.

## Why This Is A Real Bug

HTTP transfer-coding names are tokens, not prefixes. `identityXYZ` is not the `identity` transfer coding. The function is specifically responsible for parsing transfer encodings and rejecting unsolicited unsupported transfer codings in this configuration. Accepting an invalid identity-prefixed token bypasses that rejection control and creates a deterministic parser fail-open condition.

The body is delivered raw in either case (no decoding is requested) so the direct disclosure impact is bounded; the concrete risk is parser-discrepancy with strict intermediaries, which can contribute to request/response-smuggling attacks against the surrounding deployment.

## Fix Requirement

Recognition of `identity` in this branch must require both:

- `namelen == 8`
- case-insensitive equality with `"identity"` over those 8 bytes

## Patch Rationale

The patch changes identity detection from prefix matching to exact token matching:

```c
bool is_identity = (namelen == 8) &&
  curl_strnequal(name, "identity", 8);
```

This preserves valid `identity` handling while ensuring longer identity-prefixed transfer-coding names are rejected as unsolicited invalid transfer codings.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/content_encoding.c b/lib/content_encoding.c
index 0224a8bfe9..a361bc080b 100644
--- a/lib/content_encoding.c
+++ b/lib/content_encoding.c
@@ -732,7 +732,8 @@ CURLcode Curl_build_unencoding_stack(struct Curl_easy *data,
        * Exception is "chunked" transfer-encoding which always must happen */
       if((is_transfer && !data->set.http_transfer_encoding && !is_chunked) ||
          (!is_transfer && data->set.http_ce_skip)) {
-        bool is_identity = curl_strnequal(name, "identity", 8);
+        bool is_identity = (namelen == 8) &&
+          curl_strnequal(name, "identity", 8);
         /* not requested, ignore */
         CURL_TRC_WRITE(data, "decoder not requested, ignored: %.*s",
                        (int)namelen, name);
```