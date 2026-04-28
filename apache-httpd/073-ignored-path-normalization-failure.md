# Ignored Path Normalization Failure

## Classification

Validation gap; severity high; confidence certain

## Affected Locations

`server/request.c:273`

## Summary

`ap_process_request_internal()` correctly checks the first `ap_normalize_path()` call, but ignores the result of the second normalization performed after encoded slash decoding. When `AllowEncodedSlashes` and `DecodeEncodedSlashes` are enabled, URL unescaping can create new `/../` segments that violate `AP_NORMALIZE_NOT_ABOVE_ROOT`. The second normalization detects this failure, but the ignored return value allows request processing to continue.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `AllowEncodedSlashes` enabled.
- `DecodeEncodedSlashes` enabled.
- Request URI path contains encoded slash dot-segments.
- Example trigger: `/%2e%2e%2fserver-status`

## Proof

The request URI path enters `ap_process_request_internal()` as `r->parsed_uri.path`.

A concrete path such as:

```text
/%2e%2e%2fserver-status
```

follows this flow:

1. The first `ap_normalize_path()` decodes unreserved dots but does not decode `%2f`, so it does not reject the path.
2. `ap_unescape_url_ex()` decodes `%2f` because encoded slash decoding is enabled.
3. The path becomes `/../server-status`.
4. The second `ap_normalize_path()` sees an above-root `..`, returns failure, and rewrites the path to `/server-status`.
5. The return value is ignored, so processing continues through location walking, translation, storage mapping, and auth phases instead of returning `HTTP_BAD_REQUEST`.

## Why This Is A Real Bug

`AP_NORMALIZE_NOT_ABOVE_ROOT` is an explicit validation invariant: above-root path traversal segments must be rejected. The first normalization enforces this invariant before URL unescaping. After encoded slash decoding, the same invariant can be violated again because `%2f` can become `/` and create new path segments.

The second normalization already detects this condition by returning failure. Ignoring that failure converts a rejected URI into an accepted normalized target URI, allowing ordinary remote requests to proceed despite core normalization marking the path invalid.

## Practical Exploit Scenario

A site enables `AllowEncodedSlashes On` (commonly required by applications that embed slash-bearing identifiers, REST APIs that use encoded path segments, or repositories storing keys with literal `/` in names) and exposes a sensitive handler under a `<Location>` that is meant to be locked down. A representative configuration:

```apache
AllowEncodedSlashes On

<Location "/server-status">
    SetHandler server-status
    Require ip 10.0.0.0/8
</Location>

<Location "/public">
    Require all granted
</Location>
```

The administrator believes the IP restriction on `/server-status` is enforced because a request for `/server-status` from outside `10.0.0.0/8` would be denied. An external attacker instead requests:

```http
GET /public/%2e%2e%2fserver-status HTTP/1.1
Host: target.example
```

The first `ap_normalize_path` runs against the still-encoded path and sees only `/public/%2e%2e%2fserver-status`, which contains no traversal segments because `%2f` is still encoded. Location walking and access checks bind to `/public`, where the policy is `Require all granted`. The unescape step then turns `%2e%2e%2f` into `../`, producing `/public/../server-status`. The second normalization detects the above-root violation and returns failure, but its return value is dropped on the floor; the path is rewritten to `/server-status` and processing continues into translation, handler dispatch, and response generation under the access control already accepted for `/public`. The status page is delivered to an external IP that should never have been able to reach it.

The same primitive lets an attacker reach any handler whose protection depends on `<Location>`-scoped rules: admin consoles bound to `/admin`, debug endpoints behind `Require valid-user`, mod_proxy reverse-proxy maps with per-location auth, or `<LocationMatch>` rules that gate sensitive subtrees. Because the bypass is purely path-shape based, no credentials, special headers, or fragile timing are required.

## Fix Requirement

Check the second `ap_normalize_path()` return value and return `HTTP_BAD_REQUEST` on failure.

## Patch Rationale

The patch makes the post-unescape normalization behave like the initial normalization. If decoding encoded slashes creates an invalid path, the request is logged as an invalid URI path and rejected immediately with `HTTP_BAD_REQUEST`.

This preserves the intended normalized-path invariant after all configured decoding has occurred.

## Residual Risk

None

## Patch

```diff
diff --git a/server/request.c b/server/request.c
index 5599b2c..d2bc4c7 100644
--- a/server/request.c
+++ b/server/request.c
@@ -265,7 +265,11 @@ AP_DECLARE(int) ap_process_request_internal(request_rec *r)
             /* Decoding slashes might have created new // or /./ or /../
              * segments (e.g. "/.%2F/"), so re-normalize.
              */
-            ap_normalize_path(r->parsed_uri.path, normalize_flags);
+            if (!ap_normalize_path(r->parsed_uri.path, normalize_flags)) {
+                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10244)
+                              "invalid URI path (%s)", r->unparsed_uri);
+                return HTTP_BAD_REQUEST;
+            }
         }
     }
```