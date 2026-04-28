# Apache HTTP Server Audit Findings

Security audit of the Apache HTTP Server, covering the core request pipeline, authentication and authorization modules, the proxy stack, HTTP/2 and ACME, the filter chain, caching, WebDAV, MPM internals, and several support tools. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 141** -- High: 18, Medium: 115, Low: 8

## Findings

### WebDAV

| # | Finding | Severity |
|---|---------|----------|
| [002](002-failed-temp-open-schedules-unowned-path-deletion.md) | Failed temp open schedules unowned path deletion | Medium |
| [003](003-out-of-bounds-read-parsing-lock-token.md) | Out-of-bounds read parsing Lock-Token | Medium |
| [027](027-not-locktokens-satisfy-lock-validation.md) | `Not` locktokens satisfy lock validation | High |
| [028](028-lock-owner-check-bypassed-in-token-scan.md) | Lock owner check bypassed in token scan | High |
| [038](038-unchecked-direct-record-copy.md) | Unchecked direct lock record copy | Medium |
| [039](039-unbounded-owner-string-scan.md) | Unbounded owner string scan | Medium |
| [040](040-unchecked-indirect-key-length.md) | Unchecked indirect key length | Medium |
| [056](056-unescaped-core-property-xml-value.md) | Unescaped core property XML value | Medium |
| [112](112-short-metadata-value-overread.md) | Short metadata value overread | Medium |
| [113](113-namespace-count-overreads-metadata-buffer.md) | Namespace count overreads metadata buffer | Medium |
| [114](114-unbounded-namespace-id-traversal.md) | Unbounded namespace ID traversal | Medium |

### Authentication and authorization

| # | Finding | Severity |
|---|---------|----------|
| [004](004-null-request-state-dereference-in-ldap-search.md) | Null request state dereference in `ldap-search` | High |
| [024](024-null-nonce-count-parsing.md) | Null nonce-count parsing | Medium |
| [080](080-unauthenticated-open-redirect-on-failed-form-auth.md) | Unauthenticated open redirect on failed form auth | Medium |
| [081](081-open-redirect-after-login-handler-authentication.md) | Open redirect after login handler authentication | Medium |
| [083](083-unchecked-optional-function-pointer-call.md) | Unchecked optional function pointer call | Medium |
| [099](099-null-optional-dbd-acquire-call.md) | Null optional DBD acquire call (authn) | Medium |
| [100](100-null-optional-dbd-acquire-call.md) | Null optional DBD acquire call (authz) | Medium |
| [109](109-unchecked-uri-slash-in-key-construction.md) | Unchecked URI slash in authn socache key construction | High |
| [137](137-fake-authorization-header-logged.md) | Fake Authorization header logged | Medium |

### Proxy

| # | Finding | Severity |
|---|---------|----------|
| [011](011-unvalidated-pasv-data-target.md) | Unvalidated PASV data target | High |
| [012](012-unverified-active-ftp-data-peer.md) | Unverified active FTP data peer | High |
| [048](048-unescaped-health-check-expression-in-manager-html.md) | Unescaped health check expression in manager HTML | Medium |
| [059](059-unbounded-fastcgi-header-buffering.md) | Unbounded FastCGI header buffering | Medium |
| [068](068-malformed-content-length-forwarded-before-validation.md) | Malformed Content-Length forwarded to AJP backend before validation | Medium |
| [076](076-out-of-bounds-pointer-on-empty-header.md) | Out-of-bounds pointer on empty header | Low |
| [093](093-proxy-v2-length-underflow-exposes-unreceived-address-bytes.md) | PROXY v2 length underflow exposes unreceived address bytes | High |
| [094](094-unbounded-health-check-body-buffering.md) | Unbounded health check body buffering | High |
| [095](095-invalid-pointer-for-empty-header-value.md) | Invalid pointer for empty health check header value | Medium |
| [096](096-empty-response-header-underflows-pointer.md) | Empty uwsgi response header underflows pointer | Medium |
| [148](148-connect-port-check-occurs-after-dns.md) | CONNECT port authorization occurs after DNS resolution | Medium |
| [153](153-negative-ready-inflates-slot-total.md) | Negative ready inflates heartbeat slot total | Medium |
| [154](154-unbounded-ready-conversion.md) | Unbounded ready conversion | Low |
| [155](155-duplicate-reverse-proxy-aliases-on-match.md) | Duplicate reverse proxy aliases on match | Medium |
| [174](174-header-length-check-omits-header-bytes.md) | AJP header length check omits header bytes | High |
| [175](175-uint8-getter-reads-at-message-end.md) | AJP uint8 getter reads at message end | Medium |
| [176](176-string-read-ignores-declared-message-length.md) | AJP string read ignores declared message length | Medium |

### HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [046](046-unlocked-shutdown-flag-write.md) | Unlocked shutdown flag write | Medium |
| [047](047-aborted-flag-race.md) | Aborted flag race | Medium |
| [058](058-nghttp2-consume-errors-ignored.md) | nghttp2 consume errors ignored | Medium |
| [063](063-per-directory-directive-enables-server-forward-proxy.md) | Per-directory `H2ProxyRequests` enables server forward proxy | Medium |
| [064](064-unbounded-priority-recursion.md) | Unbounded HTTP/2 priority recursion | Medium |
| [065](065-option-allocation-failure-returns-success.md) | Option allocation failure returns success | Medium |
| [071](071-zero-capacity-integer-queue-modulo.md) | Zero-capacity integer queue modulo | Medium |
| [072](072-unsynchronized-ififo-count-read.md) | Unsynchronized `h2_ififo_count` read | Low |
| [088](088-signed-overflow-in-power-of-two-rounding.md) | Signed overflow in power-of-two rounding | Medium |
| [129](129-host-authority-mismatch-is-silently-overwritten.md) | Host authority mismatch is silently overwritten | Medium |
| [151](151-termination-does-not-wake-fifo-waiters.md) | FIFO termination does not wake blocked waiters | Medium |
| [152](152-capacity-one-fifo-misses-not-full-signal.md) | Capacity-one FIFO misses `not_full` signal | Medium |

### Cache

| # | Finding | Severity |
|---|---------|----------|
| [016](016-unbounded-cache-metadata-allocation.md) | Unbounded cache metadata allocation | Medium |
| [017](017-unchecked-cache-format-read.md) | Unchecked cache format read | Medium |
| [018](018-unchecked-file-info-read.md) | Unchecked file info read | Medium |
| [025](025-signed-overflow-in-freshness-calculation.md) | Signed overflow in freshness calculation | Medium |
| [026](026-negative-min-fresh-extends-cache-freshness.md) | Negative `min-fresh` extends cache freshness | Medium |
| [053](053-short-cache-entry-reads-missing-format.md) | Short cache entry reads missing format | Medium |
| [054](054-truncated-vary-entry-reads-expire.md) | Truncated Vary entry reads expire | Medium |
| [055](055-cr-terminated-vary-array-overreads-buffer.md) | CR-terminated Vary array overreads buffer | Medium |
| [084](084-cross-origin-cache-invalidation-ignores-scheme-and-port.md) | Cross-origin cache invalidation ignores scheme and port | Medium |
| [102](102-unescaped-memcached-status-html.md) | Unescaped memcached status HTML | Medium |

### SSL / TLS

| # | Finding | Severity |
|---|---------|----------|
| [019](019-passphrase-bytes-left-uncleared.md) | Passphrase bytes left uncleared | Medium |
| [029](029-per-directory-passphrase-directive-executes-commands.md) | Per-directory passphrase directive executes commands | Medium |
| [041](041-alpn-selection-accepts-protocol-prefixes.md) | ALPN selection accepts protocol prefixes | Medium |
| [049](049-challenge-credential-errors-reported-as-success.md) | Challenge credential errors reported as success | Medium |
| [050](050-uninitialized-ocsp-hook-outputs.md) | Uninitialized OCSP hook outputs | Medium |
| [107](107-partial-send-corrupts-ocsp-request.md) | Partial send corrupts OCSP request | High |
| [108](108-commonname-accepted-despite-dns-san.md) | commonName accepted despite DNS SAN | Medium |
| [149](149-certificate-controlled-ocsp-request-host.md) | Certificate-controlled OCSP request host | Medium |
| [150](150-oid-object-leak-on-absent-certificate.md) | OID object leak on absent certificate | Medium |

### ACME and mod_md

| # | Finding | Severity |
|---|---------|----------|
| [066](066-dns-hook-argument-injection.md) | DNS hook argument injection | Medium |
| [067](067-dns-teardown-argument-injection.md) | DNS teardown argument injection | Medium |
| [120](120-ocsp-response-times-accepted-without-validity-check.md) | OCSP response times accepted without validity check | Medium |
| [143](143-link-up-header-becomes-fetch-url.md) | `Link rel=up` header becomes fetch URL | Medium |
| [144](144-subjectaltname-config-injection-via-comma.md) | subjectAltName config injection via comma | Medium |
| [145](145-tls-alpn-subjectaltname-config-injection.md) | tls-alpn subjectAltName config injection | Medium |
| [159](159-wrong-certificate-index-during-freeze.md) | Wrong certificate index during freeze | Medium |
| [169](169-null-type-in-acme-problem-handling.md) | Null ACME problem type dereference | Medium |
| [170](170-authz-dereference-after-failed-retrieval.md) | authz dereference after failed retrieval | Medium |
| [171](171-unfinished-multi-requests-report-success.md) | Unfinished multi requests report success | Medium |
| [172](172-header-validation-error-ignored.md) | Header validation error ignored | Low |
| [201](201-unchecked-certificate-chain-index.md) | Unchecked certificate chain index | Medium |

### Filters

| # | Finding | Severity |
|---|---------|----------|
| [031](031-subrequest-leak-in-ssi-include.md) | SSI include subrequest pool leak | Medium |
| [057](057-filter-errors-are-discarded.md) | Filter errors are discarded | Medium |
| [075](075-edit-zero-length-match-recursion.md) | `edit*` zero-length match recursion | Medium |
| [116](116-request-body-length-desynchronization.md) | Request body length desynchronization | Medium |
| [117](117-input-filtering-bypass-by-read-mode.md) | InputSed filtering bypass by read mode | Medium |
| [124](124-unchecked-bucket-read-in-request-inflate.md) | Unchecked bucket read in request inflate | Medium |
| [125](125-unchecked-bucket-read-in-proxy-inflate.md) | Unchecked bucket read in proxy inflate | Medium |
| [126](126-wrong-filter-checked-before-insertion.md) | Wrong filter checked before insertion | Medium |
| [130](130-out-of-bounds-read-on-trailing-cr.md) | Out-of-bounds read on trailing CR | Medium |
| [140](140-stale-provider-match-state.md) | Stale provider match state | Medium |
| [141](141-out-of-bounds-read-in-meta-header-scan.md) | Out-of-bounds read in META header scan | High |
| [161](161-infinite-loop-on-empty-backreference-star.md) | Infinite loop on empty starred backreference | Medium |
| [162](162-unchecked-content-length-accumulation.md) | Unchecked content length accumulation | Medium |
| [194](194-signed-overflow-parsing-rate-limit.md) | Signed overflow parsing rate limit | Medium |
| [195](195-signed-overflow-parsing-initial-burst.md) | Signed overflow parsing initial burst | Low |
| [196](196-output-buffer-length-not-adjusted-after-skip.md) | Output buffer length not adjusted after skip | High |
| [197](197-null-convset-retained-in-conversion-loop.md) | Null convset retained in conversion loop | Medium |
| [198](198-block-nesting-stack-overflow.md) | Block nesting stack overflow | Medium |

### Generators and directory listings

| # | Finding | Severity |
|---|---------|----------|
| [044](044-unescaped-module-names-in-html-attributes.md) | Unescaped module names in server-info HTML | Medium |
| [045](045-unescaped-hook-names-in-links.md) | Unescaped hook names in links | Medium |
| [085](085-unescaped-alt-text-in-row-class.md) | Unescaped alt text in row class | Medium |
| [086](086-unescaped-alt-text-in-image-alt.md) | Unescaped alt text in image alt | Medium |

### Mappers and content negotiation

| # | Finding | Severity |
|---|---------|----------|
| [092](092-out-of-bounds-uri-suffix-comparison.md) | Out-of-bounds URI suffix comparison | High |
| [103](103-unescaped-notes-in-error-html.md) | Unescaped variant list fields in error HTML | Medium |
| [167](167-unescaped-imagemap-comments-in-html-menu.md) | Unescaped imagemap comments in HTML menu | Medium |

### CGI

| # | Finding | Severity |
|---|---------|----------|
| [033](033-short-write-reported-successful.md) | Short write reported successful | Medium |
| [034](034-short-writev-reported-successful.md) | Short `writev` reported successful | Medium |
| [035](035-uninitialized-pid-cleanup.md) | Uninitialized PID cleanup | Medium |

### MPM and process management

| # | Finding | Severity |
|---|---------|----------|
| [005](005-utf-8-conversion-writes-into-argv-buffer.md) | UTF-8 conversion writes into argv buffer | Medium |
| [013](013-out-of-range-worker-factor-conversion.md) | Out-of-range worker factor conversion | Medium |
| [014](014-pollset-size-multiplication-wraps.md) | Pollset size multiplication wraps | Medium |
| [015](015-transaction-pool-leak-on-queue-failure.md) | Transaction pool leak on queue failure | Low |
| [042](042-prefix-instance-id-accepted.md) | Prefix instance ID accepted | Medium |
| [051](051-racy-maxconnectionsperchild-counter.md) | Racy `MaxConnectionsPerChild` counter | Medium |
| [052](052-listener-thread-handle-leak.md) | Listener thread handle leak | Low |
| [097](097-out-of-bounds-scoreboard-read.md) | Out-of-bounds scoreboard read | Medium |
| [121](121-unsynchronized-thread-handle-close.md) | Unsynchronized thread handle close | Medium |

### Cluster heartbeat

| # | Finding | Severity |
|---|---------|----------|
| [060](060-out-of-bounds-terminator-write-for-maximum-heartbeat-body.md) | Out-of-bounds terminator write for maximum heartbeat body | High |
| [061](061-missing-busy-field-check-before-atoi.md) | Missing busy/ready field check before `atoi` | Medium |

### Lua

| # | Finding | Severity |
|---|---------|----------|
| [089](089-resultset-use-after-pool-destroy.md) | Resultset use after pool destroy | Medium |
| [090](090-prepared-select-uses-closed-pool.md) | Prepared select uses closed pool | Medium |
| [091](091-prepared-query-uses-closed-pool.md) | Prepared query uses closed pool | Medium |
| [166](166-unchecked-crypt-result-reaches-strcmp.md) | Unchecked `crypt` result reaches `strcmp` | Medium |

### Server core and request processing

| # | Finding | Severity |
|---|---------|----------|
| [030](030-malformed-form-percent-escapes-decoded.md) | Malformed form percent escapes decoded | Medium |
| [062](062-path-info-controls-extension-handler.md) | `PATH_INFO` controls extension handler | Medium |
| [069](069-htaccess-cache-omits-override-list.md) | htaccess cache omits `override_list` | Medium |
| [073](073-ignored-path-normalization-failure.md) | Ignored path normalization failure | High |
| [098](098-unchecked-expression-file-read.md) | Unchecked expression `file()` read | Medium |
| [193](193-signed-nametable-decoding-permits-negative-captures.md) | Signed nametable decoding permits negative captures | Medium |
| [202](202-substitution-n-flag-dereferences-null-pmatch.md) | Substitution `N` flag dereferences null `pmatch` | High |
| [203](203-global-zero-length-match-recurses-forever.md) | Global zero-length match recurses forever | Medium |

### Metadata modules

| # | Finding | Severity |
|---|---------|----------|
| [010](010-negative-indirect-offset-read.md) | Negative indirect offset read in `mod_mime_magic` | High |
| [106](106-unique-id-counter-wraps-early.md) | `mod_unique_id` counter wraps early | Medium |

### Slot memory

| # | Finding | Severity |
|---|---------|----------|
| [179](179-slot-allocation-size-overflow.md) | Slot allocation size overflow | Medium |

### Windows and platform support

| # | Finding | Severity |
|---|---------|----------|
| [022](022-request-load-failure-leaks-write-lock.md) | ISAPI request load failure leaks write lock | Medium |
| [156](156-console-title-suffix-overflows-stack-buffer.md) | Console title suffix overflows stack buffer | Medium |
| [157](157-uninitialized-application-name-passed-to-createprocess.md) | Uninitialized application name passed to `CreateProcess` | Low |
| [158](158-relative-chrootdir-re-resolution.md) | Relative `ChrootDir` re-resolution | Medium |

### Support tools

| # | Finding | Severity |
|---|---------|----------|
| [021](021-docroot-prefix-bypass.md) | suexec docroot prefix bypass | High |
| [032](032-unchecked-cache-name-length-allocation.md) | htcacheclean unchecked cache name length allocation | Medium |
| [136](136-newline-injection-in-digest-file-records.md) | htdigest newline injection in digest file records | Medium |
