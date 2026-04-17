# Signed URL drops explicit port and userinfo

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `rust/src/lib.rs:105`
- `rust/src/lib.rs:150`
- `rust/src/lib.rs:156`

## Summary
The Rust signer reconstructs the returned URL base with only `scheme://host`, omitting explicit port and any userinfo from the caller-supplied URL. As a result, successful signing of inputs such as `https://user:pass@example.com:8443/file` returns a signed URL rooted at `https://example.com/...`, changing the requested authority and credential context.

## Provenance
- Verified from the provided reproducer and source inspection in `rust/src/lib.rs`
- Reference: https://swival.dev

## Preconditions
- Caller supplies a URL with explicit port or userinfo

## Proof
At `rust/src/lib.rs:105`, the code rebuilds the base as `format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))`, which preserves only scheme and host. The resulting `base` is then used in both successful return paths at `rust/src/lib.rs:150` and `rust/src/lib.rs:156`.

Using input `https://user:pass@example.com:8443/file`, a successful call returns a signed URL of the form:
```text
https://example.com/file?token=...&expires=1598024587
```
This output drops both `user:pass@` and `:8443`, despite those components being present in the parsed input URL.

## Why This Is A Real Bug
This is not cosmetic. The function returns a URL targeting a different authority than the one the caller selected. Dropping `:8443` changes the network endpoint, and dropping userinfo changes the authentication context embedded in the URL. Because signing still succeeds, callers receive a syntactically valid but semantically different URL, causing integrity loss in the signed output.

## Fix Requirement
Reconstruct the returned URL from the parsed URL while preserving authority components, including username, password, and explicit port, instead of rebuilding from only scheme and host.

## Patch Rationale
The patch updates the Rust implementation to preserve the full parsed authority when constructing the returned signed URL. This aligns returned URLs with caller input and with the behavior already present in the C# implementation, preventing silent origin changes while keeping signing behavior otherwise unchanged.

## Residual Risk
None

## Patch
- Patch file: `001-signed-url-drops-explicit-port-and-userinfo.patch`