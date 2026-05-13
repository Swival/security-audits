# CRLF Accepted In Signed Header Value

## Classification

header injection, medium severity

## Affected Locations

- `src/s3_signing/credentials.rs:717`
- `src/s3_signing/credentials.rs:923`
- `src/http/Headers.rs:55`
- `src/http/Headers.rs:60`
- `src/http/lib.rs:1146`
- `src/http/lib.rs:1149`
- `src/http/lib.rs:1150`

## Summary

The non-presigned S3 signing path accepted CR/LF bytes in signed header values, including attacker-controlled `content_disposition`. `sign_request` copied the raw value into a `PicoHeader`, and downstream HTTP serialization wrote the value verbatim, allowing embedded CRLF to delimit additional headers in the privileged S3 request.

## Provenance

Found by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A lower-privileged caller can choose `content_disposition` for a non-presigned S3 signing request.
- The resulting `SignResult.headers()` are used to issue a privileged HTTP request.

## Proof

The reproduced flow shows:

- `content_disposition` reaches non-query `sign_request` as caller-controlled bytes.
- The non-query path creates a `content-disposition` `PicoHeader` from the raw value.
- `SignResult.headers()` exposes that header to the privileged request path.
- Header serialization copies the raw header value into the request buffer and writes `name: `, then the raw value, then `\r\n`.
- If the value contains `\r\nInjected-Header: value`, those bytes become an additional HTTP header line on the wire.
- Existing validation in `src/runtime/webcore/s3/credentials_jsc.rs:258` only covers credentials-level `contentDisposition`; it does not cover the `Blob.rs` write option path.
- The helper `contains_newline_or_cr` existed in `src/s3_signing/credentials.rs` but was not called before `PicoHeader` creation.

## Why This Is A Real Bug

HTTP header values must not contain raw CR or LF because those bytes terminate the current header line. Here, the signing layer accepted untrusted bytes and the HTTP layer serialized them verbatim. The resulting request can contain attacker-delimited extra headers while using privileged S3 credentials and a valid signing result.

## Fix Requirement

Reject CR and LF in all signed header values before creating any `PicoHeader` for the non-presigned request path.

## Patch Rationale

The patch adds a single validation gate immediately before non-query `SignResult` header construction. It checks every value that will be emitted as a signed HTTP header:

- `x-amz-content-sha256`
- `x-amz-date`
- `Host`
- `Authorization`
- `x-amz-acl`
- `x-amz-security-token`
- `x-amz-storage-class`
- `content-disposition`
- `content-encoding`
- `content-md5`

If any value contains CR or LF, signing fails with the new `SignError::InvalidHeaderValue`. This prevents raw attacker-controlled CRLF from reaching `PicoHeader` and preserves existing behavior for valid header values.

## Residual Risk

None

## Patch

```diff
diff --git a/src/s3_signing/credentials.rs b/src/s3_signing/credentials.rs
index 953f90e9b5..681a3b691e 100644
--- a/src/s3_signing/credentials.rs
+++ b/src/s3_signing/credentials.rs
@@ -871,6 +871,20 @@ impl S3Credentials {
             return Ok(r);
         }
 
+        if contains_newline_or_cr(aws_content_hash)
+            || contains_newline_or_cr(&amz_date)
+            || contains_newline_or_cr(&host)
+            || contains_newline_or_cr(&authorization)
+            || acl.is_some_and(contains_newline_or_cr)
+            || session_token.is_some_and(contains_newline_or_cr)
+            || storage_class.is_some_and(contains_newline_or_cr)
+            || content_disposition.is_some_and(contains_newline_or_cr)
+            || content_encoding.is_some_and(contains_newline_or_cr)
+            || content_md5.as_deref().is_some_and(contains_newline_or_cr)
+        {
+            return Err(SignError::InvalidHeaderValue);
+        }
+
         let url = alloc_print!(
             "{}://{}{}{}",
             protocol,
@@ -1273,6 +1287,8 @@ pub enum SignError {
     InvalidEndpoint,
     #[error("InvalidSessionToken")]
     InvalidSessionToken,
+    #[error("InvalidHeaderValue")]
+    InvalidHeaderValue,
     #[error("FailedToGenerateSignature")]
     FailedToGenerateSignature,
     #[error("NoSpaceLeft")]
```