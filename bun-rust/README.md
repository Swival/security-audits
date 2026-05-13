## Bun (Rust Port) Audit Findings

Security audit of the in-progress Rust port of [Bun](https://bun.sh), the JavaScript/TypeScript runtime, bundler, package manager and test runner. Each finding includes a detailed write-up and a patch.

The audit was run against the `rust` branch of Bun at git HEAD `13f9cff919848ef0b25d4feda0f9bac86280ff8e`, dated May 12, 17:49:03.

## Summary

**Total findings: 105** -- High: 34, Medium: 67, Low: 4

## Findings

### TLS and cryptography

| # | Finding | Severity |
|---|---------|----------|
| [001](001-csprng-is-a-no-op-on-android-and-other-unix-targets.md) | CSPRNG no-op on Android and unsupported Unix targets | High |
| [008](008-ip-address-tls-endpoints-skip-hostname-verification.md) | IP-address TLS endpoints skip hostname verification | High |
| [034](034-verify-full-skips-hostname-check-without-sni.md) | VerifyFull skips hostname check without configured SNI | High |
| [041](041-server-chosen-rsa-key-receives-password-encryption.md) | Server-chosen RSA key receives password encryption | High |
| [050](050-ssl-require-downgrades-to-plaintext.md) | `sslmode=require` downgrades to plaintext | High |
| [051](051-verifyfull-skips-hostname-without-sni.md) | VerifyFull skips hostname without SNI | High |
| [071](071-utf8-cache-output-skips-integrity-check.md) | UTF-8 cache output skips integrity check | High |
| [103](103-scryptsync-ignores-derivation-errors.md) | `scryptSync` ignores derivation errors | High |
| [079](079-malformed-ip-san-causes-out-of-bounds-read.md) | Malformed IP SAN causes out-of-bounds read | Medium |
| [099](099-md5-sha1-evp-wrapper-underallocates-digest-output.md) | MD5-SHA1 EVP wrapper underallocates digest output | Low |

### Package manager and lockfiles

| # | Finding | Severity |
|---|---------|----------|
| [005](005-git-committish-is-parsed-as-git-log-option.md) | Git committish parsed as `git-log` option | High |
| [011](011-fixed-temp-node-shim-trusts-preexisting-symlink.md) | Fixed temp node shim trusts preexisting symlink | High |
| [012](012-bin-paths-escape-the-package-root.md) | Bin paths escape the package root | High |
| [054](054-npm-tarball-url-can-receive-registry-authorization.md) | npm tarball URL can receive registry authorization | High |
| [094](094-crafted-lockfile-offsets-create-misaligned-typed-slices.md) | Crafted lockfile offsets create misaligned typed slices | High |
| [111](111-streaming-decompression-has-no-output-limit.md) | Streaming decompression has no output limit | High |
| [010](010-publishconfig-tag-injects-dist-tags.md) | `publishConfig` tag injects dist-tags | Medium |
| [013](013-package-name-controls-tarball-output-path.md) | Package name controls tarball output path | Medium |
| [018](018-duplicate-credentials-survive-cross-origin-redirect-strippin.md) | Duplicate credentials survive cross-origin redirect stripping | Medium |
| [020](020-invalid-whoami-json-aborts-package-manager.md) | Invalid `whoami` JSON aborts package manager | Medium |
| [023](023-non-2xx-streamed-tarball-responses-buffer-without-a-cap.md) | Non-2xx streamed tarball responses buffer without a cap | Medium |
| [024](024-unbounded-cache-folder-name-copy-overflows-fixed-buffer.md) | Unbounded cache folder name copy overflows fixed buffer | Medium |
| [042](042-archive-files-trusts-declared-entry-size.md) | Archive files trusts declared entry size | Medium |
| [060](060-aborted-pending-response-leaks-heap-allocation.md) | Aborted pending response leaks heap allocation | Medium |
| [065](065-empty-yarn-spec-panics-name-extraction.md) | Empty Yarn spec panics name extraction | Medium |
| [066](066-malformed-os-metadata-panics-parser.md) | Malformed `os` metadata panics Yarn lockfile parser | Medium |
| [067](067-npm-alias-resolved-path-panics-extraction.md) | npm alias resolved path panics extraction | Medium |
| [070](070-overlong-bin-name-panics-linker.md) | Overlong bin name panics linker | Medium |
| [072](072-tar-entry-size-drives-unchecked-allocation.md) | Tar entry size drives unchecked allocation | Medium |
| [086](086-duplicate-git-url-underflows-remaining-counter.md) | Duplicate git URL underflows remaining counter | Medium |
| [093](093-odd-length-shasum-panics-parser.md) | Odd-length shasum panics parser | Medium |
| [095](095-overlong-package-path-panics-during-dependency-resolution.md) | Overlong package path panics during dependency resolution | Medium |
| [096](096-overlong-bundled-dependency-path-panics-during-parse.md) | Overlong bundled dependency path panics during parse | Medium |
| [098](098-tar-entry-size-drives-unbounded-allocation.md) | Tar entry size drives unbounded allocation | Medium |
| [108](108-crafted-dependency-path-overflows-path-buffer.md) | Crafted dependency path overflows path buffer | Medium |
| [109](109-malformed-workspace-version-arrays-panic-loader.md) | Malformed workspace version arrays panic loader | Medium |
| [047](047-root-link-lockfile-entry-crashes-migration.md) | Root link lockfile entry crashes migration | Low |

### Patch subcommand

| # | Finding | Severity |
|---|---------|----------|
| [055](055-patch-deletion-path-escapes-patch-directory.md) | Patch deletion path escapes patch directory | High |
| [056](056-patch-creation-path-escapes-patch-directory.md) | Patch creation path escapes patch directory | High |

### Parser, lexer and transpiler

| # | Finding | Severity |
|---|---------|----------|
| [046](046-long-flat-brace-token-stream-wraps-parser-cursor.md) | Long flat brace token stream wraps parser cursor | High |
| [068](068-multibyte-eof-codepoint-overreads-source-buffer.md) | Multibyte EOF codepoint overreads source buffer | High |
| [097](097-unsafe-wtf-8-decoder-forms-out-of-bounds-array-reference.md) | Unsafe WTF-8 decoder forms out-of-bounds array reference | High |
| [002](002-crafted-jsx-like-object-panics-console-formatter.md) | Crafted JSX-like object panics console formatter | Medium |
| [006](006-malformed-package-script-value-panics.md) | Malformed package script value panics | Medium |
| [025](025-empty-jsx-entity-panics-the-lexer.md) | Empty JSX entity panics lexer | Medium |
| [026](026-leading-out-of-range-unicode-escape-panics.md) | Leading out-of-range Unicode escape panics | Medium |
| [040](040-malformed-inline-sourcemap-url-panics-parser.md) | Malformed inline sourcemap URL panics parser | Medium |
| [045](045-parseargs-panics-on-throwing-argument-coercion.md) | `parseArgs` panics on throwing argument coercion | Medium |
| [052](052-non-string-serve-plugin-value-panics.md) | Non-string `serve` plugin value panics | Medium |
| [053](053-recursive-declare-modifiers-exhaust-parser-stack.md) | Recursive `declare` modifiers exhaust parser stack | Medium |
| [057](057-dotted-namespace-recursion-exhausts-parser-stack.md) | Dotted namespace recursion exhausts parser stack | Medium |
| [058](058-template-literal-macro-invocation-panics.md) | Template literal macro invocation panics | Medium |
| [077](077-eof-comment-in-directive-loops-forever.md) | EOF comment in directive loops forever | Medium |
| [081](081-truncated-utf8-literal-panics-parser.md) | Truncated UTF-8 literal panics parser | Medium |
| [092](092-unbounded-recursive-array-parsing.md) | Unbounded recursive array parsing | Medium |
| [113](113-oversized-source-map-panics-while-reporting-parse-errors.md) | Oversized source map panics while reporting parse errors | Medium |
| [115](115-malformed-bun-length-panics-parser.md) | Malformed `.bun` length panics parser | Medium |

### Bundler and source maps

| # | Finding | Severity |
|---|---------|----------|
| [075](075-unescaped-macro-name-injects-generated-macro-wrapper.md) | Unescaped macro name injects generated macro wrapper | High |
| [105](105-raw-multiline-path-comment-injects-bundle-code.md) | Raw multiline path comment injects bundle code | High |
| [029](029-unescaped-route-filename-injects-into-generated-html.md) | Unescaped route filename injects into generated HTML | Medium |
| [090](090-sourcemap-original-line-indexes-coverage-hits-out-of-bounds.md) | Sourcemap original line indexes coverage hits out of bounds | Medium |
| [114](114-unescaped-css-source-path-breaks-out-of-generated-comment.md) | Unescaped CSS source path breaks out of generated comment | Medium |
| [091](091-newline-in-source-path-injects-lcov-records.md) | Newline in source path injects LCOV records | Low |

### Markdown rendering

| # | Finding | Severity |
|---|---------|----------|
| [082](082-tag-filter-emits-raw-body-text-after-escaping-disallowed-ope.md) | Tag filter emits raw body text after escaping disallowed opener | High |
| [083](083-carriage-return-bypasses-disallowed-tag-detection.md) | Carriage return bypasses disallowed tag detection | High |
| [076](076-unmatched-emphasis-delimiters-cause-quadratic-parsing.md) | Unmatched emphasis delimiters cause quadratic parsing | Medium |
| [085](085-unresolved-color-parsing-bypasses-nesting-limit.md) | Unresolved color parsing bypasses nesting limit | Medium |
| [112](112-quadratic-reference-definition-duplicate-checks.md) | Quadratic reference definition duplicate checks | Medium |

### Routing

| # | Finding | Severity |
|---|---------|----------|
| [017](017-malformed-optional-catchall-route-panics-validation.md) | Malformed optional catchall route panics validation | Medium |
| [048](048-missing-parameter-segment-panics-route-matching.md) | Missing parameter segment panics route matching | Medium |
| [049](049-catch-all-route-panics-after-64-segments.md) | Catch-all route panics after 64 segments | Medium |

### HTTP, HTTP/2 and WebSocket

| # | Finding | Severity |
|---|---------|----------|
| [039](039-peer-max-frame-size-zero-causes-continuation-loop.md) | Peer max frame size zero causes continuation loop | High |
| [009](009-incomplete-upgrade-response-buffers-without-limit.md) | Incomplete upgrade response buffers without limit | Medium |
| [037](037-crlf-accepted-in-signed-header-value.md) | CRLF accepted in signed header value | Medium |
| [100](100-unbounded-request-body-buffering.md) | Unbounded request body buffering | Medium |
| [116](116-unref-nested-worker-can-outlive-parent-vm.md) | `unref` nested worker can outlive parent VM | Medium |
| [027](027-encoded-slash-check-runs-after-percent-decoding.md) | Encoded slash check runs after percent decoding | Medium |

### Redis / RESP client

| # | Finding | Severity |
|---|---------|----------|
| [101](101-unbounded-resp-aggregate-length-allocation.md) | Unbounded RESP aggregate length allocation | High |
| [036](036-incomplete-resp-frames-are-buffered-without-limit.md) | Incomplete RESP frames buffered without limit | Medium |

### S3 and Blob storage

| # | Finding | Severity |
|---|---------|----------|
| [014](014-blob-backed-images-skip-encoded-file-size-cap.md) | Blob-backed images skip encoded file size cap | Medium |
| [033](033-s3-blob-reads-leak-downloaded-bodies.md) | S3 blob reads leak downloaded bodies | Medium |
| [061](061-oversized-uploadid-panics-fixed-query-buffer.md) | Oversized `UploadId` panics fixed query buffer | Medium |
| [062](062-malformed-s3-error-xml-panics-tag-slicing.md) | Malformed S3 error XML panics tag slicing | Medium |
| [074](074-malformed-s3-error-message-panics.md) | Malformed S3 error message panics | Medium |

### Shell builtins and command execution

| # | Finding | Severity |
|---|---------|----------|
| [004](004-nested-subshells-recurse-without-limit.md) | Nested subshells recurse without limit | Medium |
| [022](022-github-actions-command-injection-via-timeout-test-name.md) | GitHub Actions command injection via timeout test name | Medium |
| [028](028-newline-in-script-path-injects-crontab-entries.md) | Newline in script path injects crontab entries | Medium |
| [064](064-recursive-env-substitution-stack-exhaustion.md) | Recursive env substitution stack exhaustion | Medium |

### File system, paths and globs

| # | Finding | Severity |
|---|---------|----------|
| [015](015-non-utf-8-paths-enter-unchecked-str-conversion.md) | Non-UTF-8 paths enter unchecked `str` conversion | High |
| [021](021-recursive-readdir-creates-concurrent-mutable-aliases.md) | Recursive `readdir` creates concurrent mutable aliases | High |
| [032](032-snapshot-updater-follows-symlinks.md) | Snapshot updater follows symlinks | High |
| [104](104-parallel-callback-creates-aliasing-mutable-references.md) | Parallel callback creates aliasing mutable references | High |
| [016](016-repeated-descriptor-receipt-leaks-previous-fd.md) | Repeated descriptor receipt leaks previous fd | Medium |
| [063](063-invalid-utf-8-glob-panics-absolute-path-slicing.md) | Invalid UTF-8 glob panics absolute-path slicing | Medium |
| [069](069-package-entry-point-escapes-project-directory.md) | Package entry point escapes project directory | Medium |
| [089](089-pollable-file-readers-ignore-highwater-backpressure.md) | Pollable file readers ignore highwater backpressure | Medium |
| [088](088-predictable-tmp-script-file-enables-local-code-injection.md) | Predictable `/tmp` script file enables local code injection | Low |

### JS bindings, memory safety and ABI

| # | Finding | Severity |
|---|---------|----------|
| [003](003-raw-sentinel-grants-js-object-reference.md) | Raw sentinel grants JS object reference | High |
| [031](031-negative-byteoffset-escapes-arraybuffer-bounds.md) | Negative `byteOffset` escapes ArrayBuffer bounds | High |
| [059](059-unsafe-decoder-forms-out-of-bounds-array-reference.md) | Unsafe decoder forms out-of-bounds array reference | High |
| [084](084-shifted-pointer-used-as-vec-allocation-base.md) | Shifted pointer used as Vec allocation base | High |
| [106](106-forged-linkedit-size-drives-unsafe-vector-length.md) | Forged LINKEDIT size drives unsafe vector length | High |
| [080](080-clamp-reduction-unwraps-removed-maximum.md) | Clamp reduction unwraps removed maximum | Medium |
| [102](102-mask-expansion-panics-after-rtl-index-drift.md) | Mask expansion panics after RTL index drift | Medium |
| [107](107-crafted-parent-chain-overflows-depth-buffer.md) | Crafted parent chain overflows depth buffer | Medium |
