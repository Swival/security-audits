# Empty port accepted as port zero

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/common/url.c:202`

## Summary
- `h2o_url_parse_hostport` accepts an authority ending in a lone `:` and normalizes the missing port to `0`.
- This causes malformed inputs such as `host:` and `http://example.com:/` to be parsed as valid authorities with explicit port zero instead of being rejected.

## Provenance
- Verified finding reproduced from scanner report and code-path analysis.
- Source: Swival Security Scanner, `https://swival.dev`

## Preconditions
- URL authority contains a host followed by a lone colon.
- Parsing reaches `h2o_url_parse_hostport` through URL or authority handling.

## Proof
- In `lib/common/url.c:202`, encountering `:` enters port parsing with an accumulator initialized to `0`.
- If the next byte is end-of-string, `/`, or `?`, the digit loop executes zero times.
- Because no check requires at least one digit after `:`, the function assigns `*port = 0` and returns success.
- This is externally reachable through `h2o_url_parse` and `parse_authority_and_path`, so malformed inputs like `http://127.0.0.1:/` and `http://example.com:/` survive validation.
- Reproduction confirms downstream impact:
  - `lib/common/socketpool.c:160` writes `htons(h2o_url_get_port(url))` into `sin_port`.
  - `lib/common/socketpool.c:189` stringifies the parsed port as `"0"` for named hosts.
  - `lib/core/request.c:87` parses `Host` authority through the same helper; `Host: example.com:` is treated as explicit port `0` rather than rejected.

## Why This Is A Real Bug
- A lone `:` in authority syntax denotes a port delimiter, so accepting zero digits is malformed parsing behavior.
- The resulting port `0` is observably consumed by networking and routing code, changing behavior rather than failing closed.
- The codebase already treats port `0` as invalid in related paths, including `src/httpclient.c:426` and `lib/handler/connect.c:1068`, which is consistent with rejection being the intended behavior.

## Fix Requirement
- Require at least one decimal digit after `:` before accepting a port.
- If no digit follows the colon, return failure instead of assigning `0`.

## Patch Rationale
- The patch adds an explicit post-`:` digit-presence check in `h2o_url_parse_hostport`.
- This is the narrowest fix because it preserves existing valid port parsing while rejecting only the malformed empty-port case at the normalization source.

## Residual Risk
- None

## Patch
```diff
*** Begin Patch
*** Add File: 024-empty-port-is-normalized-to-port-zero.patch
diff --git a/lib/common/url.c b/lib/common/url.c
index 1111111..2222222 100644
--- a/lib/common/url.c
+++ b/lib/common/url.c
@@ -199,6 +199,10 @@ const char *h2o_url_parse_hostport(const char *s, size_t len, h2o_iovec_t *host,
         if (*s == ':') {
             ++s;
             uint32_t p = 0;
+            if (s == end || *s == '/' || *s == '?') {
+                return NULL;
+            }
             for (; s != end; ++s) {
                 if ('0' <= *s && *s <= '9') {
                     p = p * 10 + *s - '0';
*** End Patch
```