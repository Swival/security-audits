# Preserve authority components when rebuilding signed URLs

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `php/url_signing.php:82`

## Summary
The signing helper parses caller-supplied URLs but rebuilds the returned URL authority from only `scheme` and `host`. As a result, any supplied `user`, `pass`, or `port` is dropped from the signed URL, changing the effective destination and stripping credentials.

## Provenance
- Verified from the provided reproducer against `php/url_signing.php`
- Scanner source: https://swival.dev

## Preconditions
- Input URL includes `port` or `userinfo`

## Proof
The function accepts a full URL, parses it, and stores `scheme`, `host`, `path`, and `query`, but does not preserve `user`, `pass`, or `port`. It then rebuilds the authority as `{$url_scheme}://{$url_host}` at `php/url_signing.php:82`, which guarantees those parsed components are discarded before the final URL is returned.

Reproducer input:
```php
sign_bcdn_url(
    'https://user:pass@example.com:8443/path?x=1',
    'secret',
    3600,
    '',
    false,
    '',
    '',
    '',
    false,
    1700000000,
    0
)
```

Observed output:
```text
https://example.com/path?token=...&x=1&expires=1700000000
```

Expected behavior is to preserve the original authority components, yielding a signed URL rooted at `https://user:pass@example.com:8443/...`.

## Why This Is A Real Bug
The function is documented to sign a full URL and accepts such input without rejecting authority subcomponents. Dropping `port` changes the network endpoint for non-default ports, and dropping `user`/`pass` removes credentials embedded in the original URL. This is a concrete integrity failure in the returned value, not a cosmetic formatting issue.

## Fix Requirement
Preserve parsed `user`, `pass`, and `port` when reconstructing the base authority for the returned signed URL.

## Patch Rationale
The patch updates URL reconstruction in `php/url_signing.php` to include optional `user`, `pass`, and `port` components when they are present in the parsed input. This keeps the returned signed URL semantically aligned with the caller-provided URL while preserving existing behavior for URLs that only contain scheme, host, path, and query.

## Residual Risk
None

## Patch
Patched in `010-port-and-userinfo-are-dropped-from-returned-url.patch`.