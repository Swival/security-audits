# Apache httpd Audit Findings

Security audit of Apache HTTP Server, the widely deployed web server. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 56** -- High: 11, Medium: 39, Low: 6

## Findings

### Core request handling

| # | Finding | Severity |
|---|---------|----------|
| [069](069-htaccess-cache-omits-override-list.md) | htaccess cache omits override_list | Medium |
| [073](073-ignored-path-normalization-failure.md) | Ignored path normalization failure | High |
| [130](130-out-of-bounds-read-on-trailing-cr.md) | Out-of-bounds read on trailing CR | Medium |

### Configuration directives and overrides

| # | Finding | Severity |
|---|---------|----------|
| [029](029-per-directory-passphrase-directive-executes-commands.md) | Per-directory passphrase directive executes commands | Medium |
| [063](063-per-directory-directive-enables-server-forward-proxy.md) | Per-directory H2ProxyRequests enables server forward proxy | Medium |

### WebDAV (mod_dav)

| # | Finding | Severity |
|---|---------|----------|
| [003](003-out-of-bounds-read-parsing-lock-token.md) | Out-of-bounds read parsing Lock-Token | Low |
| [027](027-not-locktokens-satisfy-lock-validation.md) | Not locktokens satisfy lock validation | High |
| [028](028-lock-owner-check-bypassed-in-token-scan.md) | Lock owner check bypassed in token scan | High |
| [056](056-unescaped-core-property-xml-value.md) | Unescaped core property XML value | Medium |

### Authentication and authorization

| # | Finding | Severity |
|---|---------|----------|
| [004](004-null-request-state-dereference-in-ldap-search.md) | Null request state dereference in ldap-search | Medium |
| [024](024-null-nonce-count-parsing.md) | Null nonce-count parsing | Medium |
| [080](080-unauthenticated-open-redirect-on-failed-form-auth.md) | Unauthenticated open redirect on failed form auth | Medium |
| [081](081-open-redirect-after-login-handler-authentication.md) | Open redirect after login handler authentication | Medium |
| [083](083-unchecked-optional-function-pointer-call.md) | Unchecked optional function pointer call in mod_authz_dbm | Medium |
| [099](099-null-optional-dbd-acquire-call.md) | Null optional DBD acquire call (password) | Medium |
| [100](100-null-optional-dbd-acquire-call.md) | Null optional DBD acquire call (realm) | Medium |
| [109](109-unchecked-uri-slash-in-key-construction.md) | Unchecked URI slash in authn socache key construction | Medium |
| [137](137-fake-authorization-header-logged.md) | Fake Authorization header logged | Medium |

### mod_ssl and OCSP

| # | Finding | Severity |
|---|---------|----------|
| [041](041-alpn-selection-accepts-protocol-prefixes.md) | ALPN selection accepts protocol prefixes | Medium |
| [108](108-commonname-accepted-despite-dns-san.md) | commonName accepted despite DNS SAN | Medium |
| [120](120-ocsp-response-times-accepted-without-validity-check.md) | OCSP response times accepted without validity check | Medium |

### HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [064](064-unbounded-priority-recursion.md) | Unbounded HTTP/2 priority recursion | Medium |
| [129](129-host-authority-mismatch-is-silently-overwritten.md) | Host authority mismatch is silently overwritten | Medium |

### mod_proxy_ftp

| # | Finding | Severity |
|---|---------|----------|
| [011](011-unvalidated-pasv-data-target.md) | Unvalidated PASV data target | High |
| [012](012-unverified-active-ftp-data-peer.md) | Unverified active FTP data peer | Medium |

### mod_proxy_ajp

| # | Finding | Severity |
|---|---------|----------|
| [068](068-malformed-content-length-forwarded-before-validation.md) | Malformed Content-Length forwarded before validation | Medium |
| [174](174-header-length-check-omits-header-bytes.md) | Header length check omits header bytes | High |
| [175](175-uint8-getter-reads-at-message-end.md) | uint8 getter reads at message end | Medium |
| [176](176-string-read-ignores-declared-message-length.md) | String read ignores declared message length | Medium |

### Other proxy backends

| # | Finding | Severity |
|---|---------|----------|
| [059](059-unbounded-fastcgi-header-buffering.md) | Unbounded FastCGI header buffering | Medium |
| [076](076-out-of-bounds-pointer-on-empty-header.md) | Out-of-bounds pointer on empty header in mod_proxy_http | Low |
| [096](096-empty-response-header-underflows-pointer.md) | Empty response header underflows pointer in mod_proxy_uwsgi | Low |

### Proxy balancer and health checks

| # | Finding | Severity |
|---|---------|----------|
| [048](048-unescaped-health-check-expression-in-manager-html.md) | Unescaped health check expression in manager HTML | Medium |
| [094](094-unbounded-health-check-body-buffering.md) | Unbounded health check body buffering | Medium |
| [095](095-invalid-pointer-for-empty-header-value.md) | Invalid pointer for empty header value | Low |
| [153](153-negative-ready-inflates-slot-total.md) | Negative ready inflates slot total | Medium |

### Heartbeat and clustering

| # | Finding | Severity |
|---|---------|----------|
| [060](060-out-of-bounds-terminator-write-for-maximum-heartbeat-body.md) | Out-of-bounds terminator write for maximum heartbeat body | High |
| [061](061-missing-busy-field-check-before-atoi.md) | Missing busy/ready field check before atoi | Medium |

### Caching

| # | Finding | Severity |
|---|---------|----------|
| [025](025-signed-overflow-in-freshness-calculation.md) | Signed overflow in freshness calculation | Medium |
| [084](084-cross-origin-cache-invalidation-ignores-scheme-and-port.md) | Cross-origin cache invalidation ignores scheme and port | Medium |

### Filters and content rewriting

| # | Finding | Severity |
|---|---------|----------|
| [075](075-edit-zero-length-match-recursion.md) | Header edit zero-length match recursion | Medium |
| [116](116-request-body-length-desynchronization.md) | Request body length desynchronization | Medium |
| [117](117-input-filtering-bypass-by-read-mode.md) | InputSed filtering bypass by read mode | Medium |
| [141](141-out-of-bounds-read-in-meta-header-scan.md) | Out-of-bounds read in META header scan | High |
| [161](161-infinite-loop-on-empty-backreference-star.md) | Infinite loop on empty starred backreference | Medium |
| [194](194-signed-overflow-parsing-rate-limit.md) | Signed overflow parsing rate limit | Medium |
| [195](195-signed-overflow-parsing-initial-burst.md) | Signed overflow parsing initial burst | Low |
| [196](196-output-buffer-length-not-adjusted-after-skip.md) | Output buffer length not adjusted after skip | High |
| [197](197-null-convset-retained-in-conversion-loop.md) | Null convset retained in conversion loop | Medium |

### Mappers and generators

| # | Finding | Severity |
|---|---------|----------|
| [035](035-uninitialized-pid-cleanup.md) | Uninitialized PID cleanup in mod_cgid | Medium |
| [092](092-out-of-bounds-uri-suffix-comparison.md) | Out-of-bounds URI suffix comparison in mod_speling | High |
| [103](103-unescaped-notes-in-error-html.md) | Unescaped variant list fields in error HTML | Medium |
| [167](167-unescaped-imagemap-comments-in-html-menu.md) | Unescaped imagemap comments in HTML menu | Medium |

### mod_remoteip

| # | Finding | Severity |
|---|---------|----------|
| [093](093-proxy-v2-length-underflow-exposes-unreceived-address-bytes.md) | PROXY v2 length underflow exposes unreceived address bytes | High |

### Support utilities

| # | Finding | Severity |
|---|---------|----------|
| [021](021-docroot-prefix-bypass.md) | suEXEC docroot prefix bypass | High |
| [136](136-newline-injection-in-digest-file-records.md) | Newline injection in digest file records | Low |
