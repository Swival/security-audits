# Malformed URLs are signed instead of rejected

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `php/url_signing.php:28`

## Summary
`sign_bcdn_url()` accepts malformed or non-absolute URL input, continues past `parse_url()`, and emits a signed malformed URL instead of rejecting it. When `scheme`, `host`, or `path` are missing, the function builds `://...` outputs and still computes a valid token over the derived path.

## Provenance
- Verified from the supplied reproducer and patch target in `php/url_signing.php`
- Reference: https://swival.dev

## Preconditions
- Attacker controls `sign_bcdn_url()` URL input

## Proof
- `sign_bcdn_url()` passes attacker-controlled `$url` into `parse_url()` at `php/url_signing.php:28` without validating success or required components.
- For malformed or hostless inputs, missing `scheme` and `host` collapse into empty strings while downstream code still derives `$url_path`, `$signature_path`, and the HMAC.
- The reproduced behavior includes an input that returns `:///?token=...&expires=1700000000`, proving signing proceeds on invalid input rather than failing.
- The malformed value propagates through URL reconstruction in `php/url_signing.php:30`, `php/url_signing.php:33`, `php/url_signing.php:96`, `php/url_signing.php:100`, `php/url_signing.php:106`, and `php/url_signing.php:109`.

## Why This Is A Real Bug
The library documentation expects a full URL, but the implementation does not enforce that requirement. Instead of rejecting malformed input, it produces signed garbage URLs that appear successfully processed by the signer. That is a concrete validation failure at a security boundary because caller-controlled input reaches token generation and output construction in an invalid state.

## Fix Requirement
Reject signing unless `parse_url()` succeeds and `scheme`, `host`, and `path` are all present and non-empty before any signature material is computed.

## Patch Rationale
The patch should enforce absolute-URL validation at the parsing boundary in `php/url_signing.php`, returning failure for malformed inputs before base reconstruction or HMAC generation. This directly matches the documented contract and prevents malformed `://...` outputs from being signed.

## Residual Risk
None

## Patch
Patched in `009-malformed-urls-become-signed-host-only-urls.patch` to validate `parse_url()` results and require non-empty `scheme`, `host`, and `path` before signing.