# Zig Standard Library Audit Findings

Security audit of the Zig standard library. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 78** -- High: 47, Medium: 30, Low: 1

## Findings

### Async I/O, scheduling, and synchronization

| # | Finding | Severity |
|---|---------|----------|
| [004](004-empty-batch-initialization-reads-before-slice.md) | Empty batch initialization underflows storage index | Medium |
| [005](005-sleep-cancellation-callback-casts-wrong-waiter-type.md) | Sleep cancellation callback uses wrong waiter type | High |
| [018](018-await-can-double-free-an-already-consumed-future.md) | Await can double-free an already-consumed future | High |
| [019](019-zero-length-read-buffer-triggers-invalid-iovec-access.md) | Zero-length read buffer triggers invalid iovec access | Medium |

### Build system, install paths, and cache

| # | Finding | Severity |
|---|---------|----------|
| [003](003-installed-header-directory-destination-accepts-unsanitized-r.md) | Installed header directory destination accepts unsanitized path | Medium |
| [011](011-output-basename-can-escape-cache-root.md) | Output basename can escape cache root | High |
| [012](012-captured-stdout-stderr-basename-can-escape-cache-root.md) | Captured stdout/stderr basename escapes cache root | High |
| [015](015-double-free-of-step-names-trailing-during-teardown.md) | Double free of step_names_trailing during teardown | High |
| [044](044-unvalidated-destination-sub-path-escapes-output-root.md) | Unvalidated destination sub_path escapes output root | High |
| [045](045-directory-copy-join-allows-traversal-outside-target-director.md) | Directory copy join allows traversal outside target | High |
| [053](053-caller-controlled-install-subpath-escapes-install-root.md) | Caller-controlled install subpath escapes install root | High |
| [054](054-header-install-file-path-accepts-unchecked-relative-path.md) | Header install file path accepts unchecked relative path | High |
| [061](061-package-root-escape-via-unvalidated-sub-path.md) | Package-root escape via unvalidated sub_path | Medium |
| [062](062-directory-creation-trusts-unsanitized-relative-path.md) | Directory creation trusts unsanitized relative path | Medium |

### HTTP, WebSocket, and URI

| # | Finding | Severity |
|---|---------|----------|
| [001](001-proxy-mode-mutates-pooled-connection-after-lookup.md) | Proxy mode mutates pooled connection after lookup | Medium |
| [023](023-unvalidated-parsed-host-reaches-trusted-hostname-output.md) | Parsed URI host bypasses HostName validation | Medium |
| [026](026-websocket-upgrade-ignores-required-connection-header.md) | WebSocket upgrade ignores required Connection header | Medium |
| [027](027-response-header-crlf-validation-disappears-without-runtime-s.md) | Response header CRLF validation drops without runtime safety | Medium |
| [028](028-request-body-assertion-trusts-malformed-methods.md) | Request body assertion trusts malformed methods | Low |

### DNS

| # | Finding | Severity |
|---|---------|----------|
| [024](024-unchecked-search-directive-overflows-fixed-buffer.md) | Unchecked search directive overflows fixed buffer | High |
| [025](025-name-expansion-accepts-reserved-label-encodings-as-pointers.md) | Reserved DNS label encodings accepted as compression pointers | Medium |

### TLS

| # | Finding | Severity |
|---|---------|----------|
| [029](029-tls-1-3-empty-plaintext-underflows-content-type-parsing.md) | TLS 1.3 empty plaintext underflows content-type parsing | High |
| [030](030-tls-1-2-record-length-subtraction-can-underflow.md) | TLS 1.2 short AEAD record triggers underflow and abort | High |
| [031](031-keyupdate-handshake-reads-byte-without-length-check.md) | KeyUpdate zero-length body causes out-of-bounds read | Medium |

### Cryptography

| # | Finding | Severity |
|---|---------|----------|
| [039](039-streaming-xof-pads-every-update-call.md) | Streaming XOF pads every update call | High |
| [040](040-streaming-cxof-pads-every-update-call.md) | Streaming CXOF pads on each update call | High |
| [049](049-release-builds-permit-mismatched-buffer-lengths.md) | Release builds permit mismatched buffer lengths in ISAP | Medium |
| [055](055-associated-data-vector-length-can-overrun-fixed-stack-buffer.md) | Associated-data vector length can overrun fixed stack buffer | Medium |
| [057](057-ctr-drbg-counter-increment-underflows-loop-index.md) | CTR-DRBG counter increment underflows loop index | High |
| [065](065-utctime-years-before-2000-are-accepted-as-20xx.md) | UTCTime 50-99 years are misparsed as 2050-2099 | High |
| [066](066-der-parser-reads-past-input-before-length-validation.md) | DER header bounds check missing before parse reads | High |
| [070](070-malformed-keychain-signature-triggers-assertion-abort.md) | Malformed keychain signature triggers assertion abort | Medium |
| [079](079-empty-oid-encoding-causes-out-of-bounds-read.md) | Empty OID encoding causes out-of-bounds read | High |
| [080](080-truncated-base-128-arc-can-overrun-input.md) | Truncated base-128 arc can overrun input | High |

### ELF and DWARF

| # | Finding | Severity |
|---|---------|----------|
| [020](020-gnu-hash-bloom-size-zero-causes-division-by-zero.md) | GNU hash zero-sized tables trigger modulo-by-zero | Medium |
| [021](021-gnu-hash-empty-bucket-underflows-chain-index.md) | GNU hash empty bucket underflows chain index | High |
| [022](022-writable-pt-load-copy-ignores-segment-file-offset.md) | Writable PT_LOAD copy ignores segment file offset | High |
| [032](032-zero-entry-symtab-triggers-division-by-zero.md) | Zero-entry symtab triggers division by zero | High |
| [033](033-symbol-name-offset-can-read-past-string-table.md) | Symbol name offset can crash ELF symbol resolution | High |
| [034](034-debug-link-filename-permits-path-traversal.md) | Debuglink filename traversal escapes intended search paths | Medium |
| [035](035-shared-lock-path-mutates-cached-module-name.md) | Shared lock path mutates cached module name | High |
| [036](036-shared-lock-path-lazily-caches-debug-info.md) | Shared lock path races lazy debug-info cache | High |
| [071](071-unchecked-high-pc-offset-can-wrap-function-ranges.md) | Unchecked high_pc offset can wrap function ranges | Medium |
| [072](072-unchecked-rnglist-length-arithmetic-can-wrap-range-end.md) | Unchecked rnglist length arithmetic can wrap range end | Medium |
| [073](073-unchecked-debug-addr-index-multiplication-can-bypass-bounds-.md) | Unchecked debug_addr offset arithmetic wraps before validation | Medium |
| [081](081-out-of-bounds-debug-addr-read-after-offset-check.md) | Out-of-bounds debug_addr read after offset check | High |
| [082](082-unvalidated-dwarf-deref-performs-arbitrary-raw-memory-reads.md) | Unvalidated DWARF deref performs arbitrary raw memory reads | High |
| [083](083-addrx-constx-use-unscaled-index-into-debug-addr.md) | addrx/constx use unscaled index into .debug_addr | Medium |
| [089](089-column-count-wraps-on-256th-register-rule.md) | Column count wraps on 256th register rule | High |

### Mach-O and macOS unwind

| # | Finding | Severity |
|---|---------|----------|
| [041](041-mach-o-header-read-occurs-before-size-validation.md) | Mach-O header read before minimum-size validation | High |
| [050](050-regular-unwind-page-bounds-ignore-page-entry-offset.md) | Regular unwind page bounds ignore page entry offset | High |
| [051](051-compressed-unwind-page-bounds-ignore-page-entry-offset.md) | Compressed unwind page bounds ignore page entry offset | High |
| [058](058-unchecked-main-string-table-index-causes-out-of-bounds-slice.md) | Unchecked main string-table index causes out-of-bounds slice | High |
| [059](059-unchecked-stab-symbol-index-causes-out-of-bounds-slice.md) | Unchecked STAB symbol index causes out-of-bounds slice | High |
| [060](060-unchecked-object-file-string-table-index-causes-out-of-bound.md) | Unchecked Mach-O string index causes out-of-bounds slice | High |

### PE / COFF / PDB / CodeView

| # | Finding | Severity |
|---|---------|----------|
| [008](008-malformed-section-name-panics-parser.md) | Malformed COFF section name panics parser | Medium |
| [009](009-data-directory-count-slices-beyond-optional-header.md) | Data directory count slices beyond optional header | High |
| [010](010-section-data-length-uses-unchecked-file-controlled-bounds.md) | Section data length uses unchecked file-controlled bounds | High |
| [067](067-unchecked-file-id-indexes-module-subsection-buffer.md) | Unchecked file_id indexes module subsection buffer | High |
| [068](068-line-subsection-headers-are-dereferenced-before-size-validat.md) | Line subsection headers read before bounds check | High |
| [069](069-inlinee-names-read-past-ipi-record-boundaries.md) | Inlinee names read past IPI record boundaries | High |

### Wasm and archive parsing

| # | Finding | Severity |
|---|---------|----------|
| [042](042-archive-symbol-table-offsets-underflow-into-out-of-bounds-sl.md) | Archive symtab offset underflow into out-of-bounds slice | High |
| [043](043-wasm-section-length-slices-without-bounds-check.md) | Wasm section length out-of-bounds slice in CheckObject | High |

### Compression and archive extraction

| # | Finding | Severity |
|---|---------|----------|
| [037](037-symlink-extraction-permits-targets-outside-destination-root.md) | Symlink extraction permits targets outside destination root | Medium |
| [064](064-single-byte-literals-section-writes-past-empty-caller-buffer.md) | Single-byte literals section writes past empty caller buffer | High |
| [077](077-block-checksums-are-parsed-but-never-verified.md) | xz block checksums are parsed but never verified | High |
| [084](084-extraction-accepts-unlimited-compressed-input.md) | Zip extraction ignores declared compressed-size boundary | High |

### Compiler IR and bitcode reader

| # | Finding | Severity |
|---|---------|----------|
| [046](046-node-deserialization-trusts-unbounded-extra-and-string-index.md) | Zoir node deserialization trusts unbounded extra and string indexes | Medium |
| [047](047-null-terminated-string-lookup-can-panic-on-malformed-offset.md) | Null-terminated string lookup panics on malformed offset | Medium |
| [048](048-compile-error-notes-slice-trusts-serialized-range.md) | Compile error notes range is unchecked | Medium |
| [075](075-unchecked-extra-index-decoding-structured-data.md) | Unchecked extra index decoding structured data | High |
| [076](076-caret-spacing-underflows-on-inconsistent-source-spans.md) | Caret spacing underflows on inconsistent source spans | Medium |
| [095](095-record-name-allocation-underflows-on-empty-operands.md) | Bitcode record name allocation underflows on empty operands | High |
| [096](096-record-decoding-dereferences-missing-first-operand.md) | Bitcode record decoding dereferences missing first operand | Medium |

### EFI device paths

| # | Finding | Severity |
|---|---------|----------|
| [090](090-adr-length-underflow-fabricates-oversized-trailing-slice.md) | ADR length underflow fabricates oversized trailing slice | Medium |
| [091](091-usb-wwid-length-underflow-overreads-serial-buffer.md) | USB WWID length underflow overreads serial buffer | Medium |
| [092](092-trailing-c-string-pointers-ignore-device-path-extent.md) | Trailing C-string pointers ignore device-path extent | Medium |
| [093](093-zero-length-node-causes-infinite-traversal.md) | Zero-length node causes infinite traversal | High |
