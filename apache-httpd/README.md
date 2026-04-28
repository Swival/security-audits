# Apache HTTP Server Audit Findings

Security audit of the Apache HTTP Server, covering the core request pipeline, authentication and authorization modules, the proxy stack, HTTP/2 and ACME, the filter chain, caching, WebDAV, MPM internals, and support tools.

## Summary

**Total retained findings: 56** -- High: 11, Medium: 39, Low: 6

This index has been reviewed to retain findings that are valid and practical security concerns. Reports that depended only on administrator-authored configuration, corrupted server-owned state, trusted module/hook misuse, obsolete platform edge cases, OOM-only behavior, or expected directive semantics were removed, along with generic logic and error-handling bugs that lack any plausible attacker leverage.

## Remote Exploitability

### Direct client reachability

These findings are reachable by an unauthenticated client when the relevant built-in module or handler is enabled and exposed:

- [003](003-out-of-bounds-read-parsing-lock-token.md) - Out-of-bounds read parsing Lock-Token (Low)
- [011](011-unvalidated-pasv-data-target.md) - Unvalidated PASV Data Target (High)
- [012](012-unverified-active-ftp-data-peer.md) - Unverified Active FTP Data Peer (Medium)
- [027](027-not-locktokens-satisfy-lock-validation.md) - Not Locktokens Satisfy Lock Validation (High)
- [028](028-lock-owner-check-bypassed-in-token-scan.md) - Lock Owner Check Bypassed In Token Scan (High)
- [060](060-out-of-bounds-terminator-write-for-maximum-heartbeat-body.md) - Out-of-Bounds Terminator Write for Maximum Heartbeat Body (High)
- [073](073-ignored-path-normalization-failure.md) - Ignored Path Normalization Failure (High)
- [080](080-unauthenticated-open-redirect-on-failed-form-auth.md) - Unauthenticated Open Redirect on Failed Form Auth (Medium)
- [081](081-open-redirect-after-login-handler-authentication.md) - Open Redirect After Login Handler Authentication (Medium)
- [084](084-cross-origin-cache-invalidation-ignores-scheme-and-port.md) - Cross-Origin Cache Invalidation Ignores Scheme And Port (Medium)
- [092](092-out-of-bounds-uri-suffix-comparison.md) - out-of-bounds URI suffix comparison (High)
- [093](093-proxy-v2-length-underflow-exposes-unreceived-address-bytes.md) - PROXY v2 length underflow exposes unreceived address bytes (High)
- [116](116-request-body-length-desynchronization.md) - request body length desynchronization (Medium)
- [129](129-host-authority-mismatch-is-silently-overwritten.md) - Host authority mismatch is silently overwritten (Medium)
- [130](130-out-of-bounds-read-on-trailing-cr.md) - Out-of-Bounds Read on Trailing CR (Medium)
- [141](141-out-of-bounds-read-in-meta-header-scan.md) - Out-of-Bounds Read in META Header Scan (High)

### Configuration or backend dependent

These findings require a non-default module/directive, a configured backend, delegated `.htaccess` or application content, an authenticated session, or another deployment-specific precondition. The individual report preconditions remain authoritative.

- [004](004-null-request-state-dereference-in-ldap-search.md) - Null Request State Dereference In ldap-search (Medium)
- [024](024-null-nonce-count-parsing.md) - Null nonce-count parsing (Medium)
- [025](025-signed-overflow-in-freshness-calculation.md) - Signed Overflow In Freshness Calculation (Medium)
- [029](029-per-directory-passphrase-directive-executes-commands.md) - Per-Directory Passphrase Directive Executes Commands (Medium)
- [035](035-uninitialized-pid-cleanup.md) - Uninitialized PID Cleanup (Medium)
- [041](041-alpn-selection-accepts-protocol-prefixes.md) - ALPN selection accepts protocol prefixes (Medium)
- [048](048-unescaped-health-check-expression-in-manager-html.md) - Unescaped Health Check Expression In Manager HTML (Medium)
- [056](056-unescaped-core-property-xml-value.md) - Unescaped Core Property XML Value (Medium)
- [059](059-unbounded-fastcgi-header-buffering.md) - Unbounded FastCGI Header Buffering (Medium)
- [061](061-missing-busy-field-check-before-atoi.md) - Missing Busy/Ready Field Check Before atoi (Medium)
- [063](063-per-directory-directive-enables-server-forward-proxy.md) - Per-Directory H2ProxyRequests Enables Server Forward Proxy (Medium)
- [064](064-unbounded-priority-recursion.md) - Unbounded HTTP/2 Priority Recursion (Medium)
- [068](068-malformed-content-length-forwarded-before-validation.md) - Malformed Content-Length Forwarded Before Validation (Medium)
- [069](069-htaccess-cache-omits-override-list.md) - htaccess Cache Omits override_list (Medium)
- [075](075-edit-zero-length-match-recursion.md) - edit* zero-length match recursion (Medium)
- [076](076-out-of-bounds-pointer-on-empty-header.md) - Out-Of-Bounds Pointer On Empty Header (Low)
- [083](083-unchecked-optional-function-pointer-call.md) - unchecked optional function pointer call (Medium)
- [094](094-unbounded-health-check-body-buffering.md) - Unbounded Health Check Body Buffering (Medium)
- [095](095-invalid-pointer-for-empty-header-value.md) - Invalid Pointer For Empty Header Value (Low)
- [096](096-empty-response-header-underflows-pointer.md) - Empty Response Header Underflows Pointer (Low)
- [099](099-null-optional-dbd-acquire-call.md) - null optional DBD acquire call (Medium)
- [100](100-null-optional-dbd-acquire-call.md) - null optional DBD acquire call (Medium)
- [103](103-unescaped-notes-in-error-html.md) - Unescaped Variant List Fields In Error HTML (Medium)
- [108](108-commonname-accepted-despite-dns-san.md) - commonName accepted despite DNS SAN (Medium)
- [109](109-unchecked-uri-slash-in-key-construction.md) - Unchecked URI Slash in Authn Socache Key Construction (Medium)
- [117](117-input-filtering-bypass-by-read-mode.md) - InputSed filtering bypass by read mode (Medium)
- [120](120-ocsp-response-times-accepted-without-validity-check.md) - OCSP response times accepted without validity check (Medium)
- [137](137-fake-authorization-header-logged.md) - Fake Authorization Header Logged (Medium)
- [153](153-negative-ready-inflates-slot-total.md) - Negative Ready Inflates Slot Total (Medium)
- [161](161-infinite-loop-on-empty-backreference-star.md) - Infinite Loop On Empty Starred Backreference (Medium)
- [167](167-unescaped-imagemap-comments-in-html-menu.md) - Unescaped Imagemap Comments in HTML Menu (Medium)
- [174](174-header-length-check-omits-header-bytes.md) - Header Length Check Omits Header Bytes (High)
- [175](175-uint8-getter-reads-at-message-end.md) - uint8 getter reads at message end (Medium)
- [176](176-string-read-ignores-declared-message-length.md) - string read ignores declared message length (Medium)
- [194](194-signed-overflow-parsing-rate-limit.md) - Signed Overflow Parsing Rate Limit (Medium)
- [195](195-signed-overflow-parsing-initial-burst.md) - signed overflow parsing initial burst (Low)
- [196](196-output-buffer-length-not-adjusted-after-skip.md) - Output Buffer Length Not Adjusted After Skip (High)
- [197](197-null-convset-retained-in-conversion-loop.md) - null convset retained in conversion loop (Medium)

### Local or platform specific

These findings are not directly remotely exploitable, but remain practical for local support tooling or setuid helper boundaries:

- [021](021-docroot-prefix-bypass.md) - docroot prefix bypass (High)
- [136](136-newline-injection-in-digest-file-records.md) - Newline Injection In Digest File Records (Low)

## Findings

### WebDAV

| # | Finding | Severity |
|---|---------|----------|
| [003](003-out-of-bounds-read-parsing-lock-token.md) | Out-of-bounds read parsing Lock-Token | Low |
| [027](027-not-locktokens-satisfy-lock-validation.md) | Not Locktokens Satisfy Lock Validation | High |
| [028](028-lock-owner-check-bypassed-in-token-scan.md) | Lock Owner Check Bypassed In Token Scan | High |
| [056](056-unescaped-core-property-xml-value.md) | Unescaped Core Property XML Value | Medium |

### Authentication and authorization

| # | Finding | Severity |
|---|---------|----------|
| [004](004-null-request-state-dereference-in-ldap-search.md) | Null Request State Dereference In ldap-search | Medium |
| [024](024-null-nonce-count-parsing.md) | Null nonce-count parsing | Medium |
| [080](080-unauthenticated-open-redirect-on-failed-form-auth.md) | Unauthenticated Open Redirect on Failed Form Auth | Medium |
| [081](081-open-redirect-after-login-handler-authentication.md) | Open Redirect After Login Handler Authentication | Medium |
| [083](083-unchecked-optional-function-pointer-call.md) | unchecked optional function pointer call | Medium |
| [099](099-null-optional-dbd-acquire-call.md) | null optional DBD acquire call | Medium |
| [100](100-null-optional-dbd-acquire-call.md) | null optional DBD acquire call | Medium |
| [109](109-unchecked-uri-slash-in-key-construction.md) | Unchecked URI Slash in Authn Socache Key Construction | Medium |
| [137](137-fake-authorization-header-logged.md) | Fake Authorization Header Logged | Medium |

### Proxy

| # | Finding | Severity |
|---|---------|----------|
| [011](011-unvalidated-pasv-data-target.md) | Unvalidated PASV Data Target | High |
| [012](012-unverified-active-ftp-data-peer.md) | Unverified Active FTP Data Peer | Medium |
| [048](048-unescaped-health-check-expression-in-manager-html.md) | Unescaped Health Check Expression In Manager HTML | Medium |
| [059](059-unbounded-fastcgi-header-buffering.md) | Unbounded FastCGI Header Buffering | Medium |
| [068](068-malformed-content-length-forwarded-before-validation.md) | Malformed Content-Length Forwarded Before Validation | Medium |
| [076](076-out-of-bounds-pointer-on-empty-header.md) | Out-Of-Bounds Pointer On Empty Header | Low |
| [093](093-proxy-v2-length-underflow-exposes-unreceived-address-bytes.md) | PROXY v2 length underflow exposes unreceived address bytes | High |
| [094](094-unbounded-health-check-body-buffering.md) | Unbounded Health Check Body Buffering | Medium |
| [095](095-invalid-pointer-for-empty-header-value.md) | Invalid Pointer For Empty Header Value | Low |
| [096](096-empty-response-header-underflows-pointer.md) | Empty Response Header Underflows Pointer | Low |
| [153](153-negative-ready-inflates-slot-total.md) | Negative Ready Inflates Slot Total | Medium |
| [174](174-header-length-check-omits-header-bytes.md) | Header Length Check Omits Header Bytes | High |
| [175](175-uint8-getter-reads-at-message-end.md) | uint8 getter reads at message end | Medium |
| [176](176-string-read-ignores-declared-message-length.md) | string read ignores declared message length | Medium |

### HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [063](063-per-directory-directive-enables-server-forward-proxy.md) | Per-Directory H2ProxyRequests Enables Server Forward Proxy | Medium |
| [064](064-unbounded-priority-recursion.md) | Unbounded HTTP/2 Priority Recursion | Medium |
| [129](129-host-authority-mismatch-is-silently-overwritten.md) | Host authority mismatch is silently overwritten | Medium |

### Cache

| # | Finding | Severity |
|---|---------|----------|
| [025](025-signed-overflow-in-freshness-calculation.md) | Signed Overflow In Freshness Calculation | Medium |
| [084](084-cross-origin-cache-invalidation-ignores-scheme-and-port.md) | Cross-Origin Cache Invalidation Ignores Scheme And Port | Medium |

### SSL / TLS

| # | Finding | Severity |
|---|---------|----------|
| [041](041-alpn-selection-accepts-protocol-prefixes.md) | ALPN selection accepts protocol prefixes | Medium |
| [108](108-commonname-accepted-despite-dns-san.md) | commonName accepted despite DNS SAN | Medium |

### ACME and mod_md

| # | Finding | Severity |
|---|---------|----------|
| [120](120-ocsp-response-times-accepted-without-validity-check.md) | OCSP response times accepted without validity check | Medium |

### Session

| # | Finding | Severity |
|---|---------|----------|
| [029](029-per-directory-passphrase-directive-executes-commands.md) | Per-Directory Passphrase Directive Executes Commands | Medium |

### Filters

| # | Finding | Severity |
|---|---------|----------|
| [075](075-edit-zero-length-match-recursion.md) | edit* zero-length match recursion | Medium |
| [116](116-request-body-length-desynchronization.md) | request body length desynchronization | Medium |
| [117](117-input-filtering-bypass-by-read-mode.md) | InputSed filtering bypass by read mode | Medium |
| [130](130-out-of-bounds-read-on-trailing-cr.md) | Out-of-Bounds Read on Trailing CR | Medium |
| [141](141-out-of-bounds-read-in-meta-header-scan.md) | Out-of-Bounds Read in META Header Scan | High |
| [161](161-infinite-loop-on-empty-backreference-star.md) | Infinite Loop On Empty Starred Backreference | Medium |
| [194](194-signed-overflow-parsing-rate-limit.md) | Signed Overflow Parsing Rate Limit | Medium |
| [195](195-signed-overflow-parsing-initial-burst.md) | signed overflow parsing initial burst | Low |
| [196](196-output-buffer-length-not-adjusted-after-skip.md) | Output Buffer Length Not Adjusted After Skip | High |
| [197](197-null-convset-retained-in-conversion-loop.md) | null convset retained in conversion loop | Medium |

### Mappers and content negotiation

| # | Finding | Severity |
|---|---------|----------|
| [092](092-out-of-bounds-uri-suffix-comparison.md) | out-of-bounds URI suffix comparison | High |
| [103](103-unescaped-notes-in-error-html.md) | Unescaped Variant List Fields In Error HTML | Medium |
| [167](167-unescaped-imagemap-comments-in-html-menu.md) | Unescaped Imagemap Comments in HTML Menu | Medium |

### CGI

| # | Finding | Severity |
|---|---------|----------|
| [035](035-uninitialized-pid-cleanup.md) | Uninitialized PID Cleanup | Medium |

### Cluster heartbeat

| # | Finding | Severity |
|---|---------|----------|
| [060](060-out-of-bounds-terminator-write-for-maximum-heartbeat-body.md) | Out-of-Bounds Terminator Write for Maximum Heartbeat Body | High |
| [061](061-missing-busy-field-check-before-atoi.md) | Missing Busy/Ready Field Check Before atoi | Medium |

### Server core and request processing

| # | Finding | Severity |
|---|---------|----------|
| [069](069-htaccess-cache-omits-override-list.md) | htaccess Cache Omits override_list | Medium |
| [073](073-ignored-path-normalization-failure.md) | Ignored Path Normalization Failure | High |

### Support tools

| # | Finding | Severity |
|---|---------|----------|
| [021](021-docroot-prefix-bypass.md) | docroot prefix bypass | High |
| [136](136-newline-injection-in-digest-file-records.md) | Newline Injection In Digest File Records | Low |
