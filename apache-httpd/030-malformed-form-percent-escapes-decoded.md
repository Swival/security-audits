# Malformed Form Percent Escapes Decoded

## Classification

Validation gap, medium severity.

## Affected Locations

`server/util.c:2873`

## Summary

`ap_parse_form_data()` decodes percent escapes in `application/x-www-form-urlencoded` request bodies without validating that both bytes after `%` are hexadecimal. Malformed escapes such as `%3=` are accepted and normalized into decoded form bytes before name/value parsing, allowing syntactically invalid form input to affect parsed parameters.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A request has an `application/x-www-form-urlencoded` body containing `%` followed by one or more non-hex bytes.

## Proof

The form parser reads request body bytes in `ap_parse_form_data()`. When it sees `%`, it enters `FORM_PERCENTA`, copies the next two bytes into `escaped_char`, and then calls `x2c(escaped_char)` directly.

`x2c()` performs arithmetic conversion without validating input bytes. Unlike URL unescaping, which checks both bytes with `apr_isxdigit()` before calling `x2c()`, the form parser had no equivalent guard.

Concrete reproduced case:

`user%3=admin`

`%3=` is malformed because `=` is not hexadecimal. The unguarded call `x2c("3=")` deterministically returns byte `0x3d`, which is `=`. In `FORM_NAME`, that decoded byte is then treated as the name/value delimiter, so the malformed input is accepted and parsed as:

`user=admin`

The same path can decode malformed escapes into control or structural bytes, for example `%0=` becoming `\r`.

## Why This Is A Real Bug

The parser is responsible for removing URL encoding from form names and values, but percent encoding is only valid when `%` is followed by two hexadecimal digits. Accepting malformed escapes creates inconsistent behavior with the URL unescape path and permits invalid wire input to be normalized into meaningful downstream form bytes.

This is reachable for every supported `application/x-www-form-urlencoded` parse through `ap_parse_form_data()`.

## Fix Requirement

Before calling `x2c()` in the form percent-decoding path, validate both collected escape bytes with `apr_isxdigit()`. If either byte is not hexadecimal, reject the request as malformed.

## Patch Rationale

The patch adds the missing validation immediately after the second escape byte is collected and before `x2c()` is called. On invalid input, it destroys the request body brigade and returns `HTTP_BAD_REQUEST`.

This mirrors the validation already used by URL unescaping and prevents malformed form percent escapes from being decoded into names or values.

## Residual Risk

None

## Patch

```diff
diff --git a/server/util.c b/server/util.c
index 11d0e40..7056af5 100644
--- a/server/util.c
+++ b/server/util.c
@@ -2870,6 +2870,10 @@ AP_DECLARE(int) ap_parse_form_data(request_rec *r, ap_filter_t *f,
                 }
                 if (FORM_PERCENTB == percent) {
                     escaped_char[1] = c;
+                    if (!apr_isxdigit(escaped_char[0]) || !apr_isxdigit(escaped_char[1])) {
+                        apr_brigade_destroy(bb);
+                        return HTTP_BAD_REQUEST;
+                    }
                     c = x2c(escaped_char);
                     percent = FORM_NORMAL;
                 }
```