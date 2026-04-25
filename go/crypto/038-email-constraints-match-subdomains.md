# Bare Email Name Constraints Incorrectly Match Subdomains

## Classification
Authorization flaw, medium severity. Confidence: certain.

## Affected Locations
`src/crypto/x509/constraints.go:426`

## Summary
Bare `rfc822Name` email constraints such as `example.com` were evaluated with DNS suffix semantics. This allowed `user@sub.example.com` even though RFC 5280 distinguishes exact bare-domain constraints from leading-dot subdomain constraints.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
A CA certificate has a bare permitted email constraint such as `example.com`.

## Proof
A constrained root with `PermittedEmailAddresses: []string{"example.com"}` incorrectly verified a leaf containing email SAN `user@sub.example.com`.

The flow was:
- Bare email constraints without `@` were stored as domain constraints.
- Email SAN parsing lowercased the mailbox domain.
- Email constraint checking passed only the mailbox domain to DNS constraint matching.
- DNS constraint matching used label-suffix logic.
- `example.com` therefore matched `sub.example.com`.

Relevant paths:
- `src/crypto/x509/parser.go:619`
- `src/crypto/x509/parser.go:625`
- `src/crypto/x509/parser.go:631`
- `src/crypto/x509/constraints.go:409`
- `src/crypto/x509/constraints.go:429`
- `src/crypto/x509/constraints.go:443`
- `src/crypto/x509/constraints.go:374`
- `src/crypto/x509/constraints.go:240`
- `src/crypto/x509/constraints.go:453`
- `src/crypto/x509/constraints.go:521`

## Why This Is A Real Bug
RFC 5280 `rfc822Name` constraints have distinct semantics:
- `example.com` matches mailboxes exactly at `example.com`.
- `.example.com` matches mailboxes in subdomains of `example.com`.

Using DNS suffix matching for bare email domains collapses these cases and expands the CA’s permitted namespace.

## Fix Requirement
Implement email-domain constraint matching separately from DNS name constraint matching:
- Bare domains must match only the exact mailbox domain.
- Leading-dot domains must match only subdomains.
- Full mailbox constraints must continue to match the full normalized mailbox.

## Patch Rationale
The patch separates `rfc822Name` domain matching from DNS constraint suffix matching so email constraints follow RFC 5280 semantics instead of DNS SAN semantics.

This prevents `example.com` from authorizing `user@sub.example.com` while preserving the intended behavior for `.example.com`.

## Residual Risk
None

## Patch
`038-email-constraints-match-subdomains.patch`