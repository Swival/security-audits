# Rust Standard Library Audit Findings

Security audit of the Rust standard library and supporting crates (`core`, `alloc`, `std`, `stdarch`, `test`, `compiler-builtins`, and friends). Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 189** -- High: 27, Medium: 149, Low: 13

## Findings

### std::sys::pal

| # | Finding | Severity |
|---|---------|----------|
| [004](004-stale-handle-count-sets-vec-length.md) | stale handle count sets Vec length | Medium |
| [005](005-zero-length-device-path-stalls-iterator.md) | Zero-Length Device Path Stalls Iterator | Low |
| [006](006-file-name-length-underflow.md) | File Name Length Underflow | Medium |
| [010](010-alternate-stack-leak-on-guard-setup-failure.md) | Alternate Stack Leak On Guard Setup Failure | Low |
| [011](011-unmapping-active-alternate-stack.md) | Unmapping Active Alternate Stack | Medium |
| [062](062-unicode-string-length-truncation.md) | UNICODE_STRING Length Truncation | Medium |
| [071](071-shared-slice-reference-over-mutable-userspace.md) | Shared Slice Reference Over Mutable Userspace | High |
| [072](072-exclusive-slice-reference-over-nonexclusive-userspace.md) | Exclusive Slice Reference Over Nonexclusive Userspace | High |
| [105](105-signed-minimum-negation-overflows.md) | Signed Minimum Negation Overflows | Medium |
| [106](106-i32-minimum-negation-overflows.md) | i32 Minimum Negation Overflows | Medium |
| [107](107-spin-mutex-bypasses-inter-core-lock.md) | Spin Mutex Bypasses Inter-Core Lock | High |
| [142](142-sockaddr-storage-too-small-for-ipv6.md) | sockaddr_storage too small for IPv6 | High |
| [143](143-invalid-minute-accepted.md) | Invalid Minute Accepted | Medium |
| [144](144-nonexistent-dates-accepted.md) | Nonexistent Dates Accepted | Medium |
| [145](145-unchecked-alignment-forms-invalid-layout.md) | Unchecked Alignment Forms Invalid Layout | Medium |
| [146](146-zero-new-size-reaches-realloc.md) | zero new size reaches realloc | Medium |
| [147](147-unchecked-parameter-length-creates-static-slice.md) | Unchecked Parameter Length Creates Static Slice | High |
| [167](167-null-pointer-passed-to-from-raw-parts.md) | null pointer passed to from_raw_parts | Medium |
| [168](168-oversized-timeout-becomes-infinite-wait.md) | Oversized Timeout Becomes Infinite Wait | Medium |
| [189](189-elapsed-time-used-as-timeout.md) | elapsed time used as timeout | Medium |
| [190](190-wrapped-enclave-limit-permits-enclave-pointers.md) | Wrapped Enclave Limit Permits Enclave Pointers | Medium |
| [192](192-unchecked-read-length-slices-user-buffer.md) | Unchecked SGX Read Length Slices User Buffer | Medium |
| [193](193-unchecked-read-length-slices-enclave-cursor.md) | unchecked read length slices enclave cursor | Medium |
| [194](194-movable-self-referential-list-pointer.md) | Movable Self-Referential List Pointer | High |

### std::sys::net

| # | Finding | Severity |
|---|---------|----------|
| [007](007-async-completion-status-read-from-stale-copy.md) | async completion status read from stale copy | Medium |
| [021](021-unchecked-receive-length-panics.md) | Unchecked Receive Length Panics | Medium |
| [022](022-read-reports-uncopied-bytes.md) | read reports uncopied bytes | Medium |
| [023](023-write-reports-excess-bytes.md) | write reports excess bytes | Medium |
| [041](041-accept-can-orphan-rebound-listener-fd.md) | accept can orphan rebound listener fd | Medium |
| [042](042-accept-ignores-response-length.md) | accept ignores response length | Medium |
| [049](049-panic-on-empty-connect-addresses.md) | Panic on Empty Connect Addresses | Medium |
| [050](050-panic-on-empty-listener-bind-addresses.md) | Panic on Empty Listener Bind Addresses | Medium |
| [051](051-panic-on-empty-udp-bind-addresses.md) | Panic On Empty UDP Bind Addresses | Medium |
| [052](052-unchecked-receive-length-panics.md) | unchecked receive length panics | Medium |
| [053](053-receive-length-overreports-copied-bytes.md) | receive length overreports copied bytes | Medium |
| [054](054-send-length-exceeds-copied-payload.md) | send length exceeds copied payload | Medium |
| [138](138-accept-masks-invalid-peer-address.md) | accept masks invalid peer address | Medium |
| [139](139-ipv6-dns-record-parsing-skips-first-byte.md) | IPv6 DNS record parsing skips first byte | Medium |
| [140](140-ipv6-dns-record-boundary-check-permits-panic.md) | IPv6 DNS Record Boundary Check Permits Panic | Medium |
| [141](141-oversized-dns-query-length-forwarded.md) | Oversized DNS Query Length Forwarded | Medium |

### std::sys::fs

| # | Finding | Severity |
|---|---------|----------|
| [008](008-unchecked-reparse-name-bounds.md) | Unchecked Reparse Name Bounds | Medium |
| [009](009-unchecked-directory-name-length.md) | unchecked directory name length | Medium |
| [018](018-unchecked-dirent-header-length.md) | unchecked dirent header length | High |
| [019](019-unbounded-directory-name-scan.md) | Unbounded Directory Name Scan | High |
| [020](020-remove-dir-all-follows-dot-entries.md) | remove_dir_all follows dot entries | High |
| [030](030-volume-handle-leak-in-from-path.md) | Volume Handle Leak In `from_path` | Medium |
| [031](031-existence-check-leaks-opened-handle.md) | Existence Check Leaks Opened Handle | Medium |
| [032](032-created-directory-handle-leak.md) | Created Directory Handle Leak | Medium |

### std::sys::process

| # | Finding | Severity |
|---|---------|----------|
| [012](012-spawned-child-leaked-on-pidfd-pid-lookup-failure.md) | Spawned Child Leaked On pidfd PID Lookup Failure | Medium |
| [025](025-early-error-leaves-redirected-stdio.md) | Early Error Leaves Redirected Stdio | High |
| [026](026-restore-failure-leaks-saved-descriptor.md) | restore failure leaks saved descriptor | Medium |
| [075](075-environment-rollback-skipped-on-start-failure.md) | Environment Rollback Skipped On Start Failure | Medium |
| [108](108-stderr-uses-stdout-configuration.md) | stderr uses stdout configuration | High |
| [109](109-cloned-handle-leaked-on-fd-creation-error.md) | Cloned Handle Leaked On fd Creation Error | Medium |
| [110](110-callback-error-leaks-stdio-descriptors.md) | callback error leaks stdio descriptors | Medium |

### std::sys::thread

| # | Finding | Severity |
|---|---------|----------|
| [043](043-stack-rounding-addition-overflows.md) | Stack Rounding Addition Overflows | Medium |
| [044](044-stack-mapping-length-overflows.md) | stack mapping length overflows | Medium |
| [055](055-task-creation-failure-leaks-thread-state.md) | task creation failure leaks thread state | Medium |
| [078](078-threadinit-leaked-on-spawn-failure.md) | ThreadInit Leaked on Spawn Failure | Medium |
| [170](170-unchecked-nonzero-construction.md) | unchecked NonZero construction | Medium |
| [171](171-early-return-on-atomic-wait-notification.md) | Early Return On Atomic Wait Notification | Medium |
| [172](172-recursive-tls-initialization-invalidates-returned-pointer.md) | Recursive TLS Initialization Invalidates Returned Pointer | Medium |

### std::sys::stdio

| # | Finding | Severity |
|---|---------|----------|
| [076](076-saved-surrogate-triggers-out-of-bounds-slice.md) | Saved Surrogate Triggers Out-Of-Bounds Slice | Medium |
| [077](077-pending-stdin-bytes-overwritten.md) | Pending stdin bytes overwritten | Medium |
| [121](121-oversized-lend-valid-length.md) | Oversized Panic GFX Lend Valid Length | Medium |
| [153](153-unchecked-vectored-write-length-sum.md) | Unchecked Vectored Write Length Sum | Medium |
| [195](195-read-count-exceeds-buffer-length.md) | read count exceeds buffer length | Medium |
| [196](196-unchecked-abi-length-advances-cursor.md) | unchecked ABI length advances cursor | High |

### std::sys::sync

| # | Finding | Severity |
|---|---------|----------|
| [111](111-timeout-can-exceed-waiter-counter.md) | timeout can exceed waiter counter | High |
| [112](112-wait-error-leaves-mutex-unlocked.md) | wait error leaves mutex unlocked | Medium |
| [113](113-notify-error-loses-waiters.md) | notify error loses waiters | Medium |
| [114](114-contended-lock-lacks-acquire-synchronization.md) | Contended Mutex Wait Path Lacks Acquire Synchronization | High |
| [169](169-no-op-downgrade-leaves-writer-lock-held.md) | No-Op RwLock Downgrade Leaves Writer Lock Held | Medium |

### std::sys::personality

| # | Finding | Severity |
|---|---------|----------|
| [148](148-unchecked-call-site-table-length-pointer-add.md) | Unchecked Call-Site Table Length Pointer Add | High |
| [150](150-lsda-controlled-indirect-pointer-dereference.md) | LSDA-Controlled Indirect Pointer Dereference | High |
| [151](151-oversized-uleb128-invalid-shift.md) | Oversized ULEB128 Invalid Shift | Medium |
| [152](152-oversized-sleb128-invalid-shift.md) | oversized SLEB128 invalid shift | Medium |

### std::sys::alloc

| # | Finding | Severity |
|---|---------|----------|
| [061](061-realloc-uses-mismatched-allocation-predicate.md) | realloc uses mismatched allocation predicate | Medium |
| [069](069-unchecked-c-allocation-layout.md) | Unchecked C Allocation Layout | Medium |
| [070](070-unchecked-c-deallocation-layout.md) | Unchecked C Deallocation Layout | Medium |
| [102](102-realloc-used-on-memalign-allocation.md) | realloc used on memalign allocation | Medium |

### std::sys::env

| # | Finding | Severity |
|---|---------|----------|
| [103](103-unsynchronized-global-pointer-dereference.md) | Unsynchronized Global Pointer Dereference | Medium |
| [104](104-global-environ-pointer-advanced-during-enumeration.md) | Global Environ Pointer Advanced During Enumeration | Medium |
| [188](188-allocation-overflow-creates-undersized-buffer.md) | allocation overflow creates undersized buffer | High |

### std::sys::args

| # | Finding | Severity |
|---|---------|----------|
| [086](086-null-load-options-slice-creation.md) | null load_options slice creation | Medium |
| [137](137-negative-argc-becomes-huge-slice-length.md) | Negative argc Becomes Huge Slice Length | High |
| [187](187-unchecked-argv-length-rounding-overflow.md) | unchecked argv length rounding overflow | Medium |

### std::sys (other)

| # | Finding | Severity |
|---|---------|----------|
| [034](034-rdrand-target-feature-skips-amd-blacklist.md) | RDRAND target feature skips AMD blacklist | Medium |
| [074](074-interior-nul-truncates-chdir-path.md) | Interior NUL Truncates Windows chdir Path | Medium |
| [087](087-drive-only-path-skips-absolutization.md) | drive-only path skips absolutization | Medium |
| [088](088-unchecked-firmware-timestamp-frequency.md) | Unchecked Firmware Timestamp Frequency | Medium |
| [166](166-positive-strerror-r-errors-ignored.md) | positive strerror_r errors ignored | Medium |

### std::os::unix

| # | Finding | Severity |
|---|---------|----------|
| [013](013-unchecked-read-exact-at-offset-addition.md) | unchecked read_exact_at offset addition | Medium |
| [014](014-unchecked-read-buf-exact-at-offset-addition.md) | unchecked read_buf_exact_at offset addition | Medium |
| [015](015-unchecked-write-all-at-offset-addition.md) | unchecked write_all_at offset addition | Medium |
| [029](029-vectored-writes-omit-sigpipe-suppression.md) | Vectored UnixStream Writes Omit SIGPIPE Suppression | Medium |
| [135](135-oversized-socket-length-panic.md) | Oversized Unix Socket Address Length Panic | Medium |

### std::os::windows

| # | Finding | Severity |
|---|---------|----------|
| [016](016-missing-default-sqos-on-windows-opens.md) | Missing Default SQOS On Windows Opens | Medium |
| [017](017-missing-cleanup-on-attribute-update-failure.md) | Missing Cleanup On Attribute Update Failure | Medium |
| [066](066-socket-clone-inheritance-race-in-fallback-path.md) | Socket Clone Inheritance Race In Fallback Path | Medium |
| [136](136-nul-bytes-accepted-in-pathname.md) | NUL Bytes Accepted in Pathname | Medium |

### std::os::xous

| # | Finding | Severity |
|---|---------|----------|
| [039](039-stale-limit-returned-on-scalar2.md) | Stale Limit Returned On Scalar2 | Medium |
| [040](040-long-service-names-are-silently-truncated.md) | Long Service Names Are Silently Truncated | Medium |

### std::os::uefi

| # | Finding | Severity |
|---|---------|----------|
| [060](060-public-globals-allow-arbitrary-pointer-dereference.md) | Public Globals Allow Arbitrary Pointer Dereference | High |

### std::io

| # | Finding | Severity |
|---|---------|----------|
| [059](059-unchecked-oversized-write-count-in-flush.md) | Unchecked Oversized Write Count In BufWriter Flush | Low |
| [132](132-vectored-write-count-overflow.md) | Vectored Write Count Overflow | Medium |
| [133](133-unchecked-empty-vectored-length-sum.md) | Unchecked Empty Vectored Length Sum | Medium |
| [134](134-unchecked-sink-vectored-length-sum.md) | unchecked Sink vectored length sum | Medium |

### std::sync

| # | Finding | Severity |
|---|---------|----------|
| [067](067-timeout-result-discarded-in-wait-timeout-while.md) | timeout result discarded in wait_timeout_while | Medium |
| [068](068-write-downgrade-skips-poison-finalization.md) | write downgrade skips poison finalization | Medium |

### std (panicking)

| # | Finding | Severity |
|---|---------|----------|
| [002](002-resume-unwind-ignores-required-abort.md) | resume_unwind ignores required abort | Medium |

### stdarch

| # | Finding | Severity |
|---|---------|----------|
| [079](079-secrets-passed-to-mutable-external-workflow.md) | Secrets Passed To Mutable External Workflow | Medium |
| [080](080-unguarded-immediate-maximum-increment.md) | Unguarded Immediate Maximum Increment | Medium |
| [081](081-undersized-v4sf-integer-view.md) | Undersized V4SF Integer View | Medium |
| [082](082-undersized-v8sf-integer-view.md) | undersized V8SF integer view | Medium |
| [089](089-unchecked-mte-tag-offset.md) | unchecked MTE tag offset | Medium |
| [090](090-out-of-range-simd-insert-index.md) | Out-of-Range SIMD Insert Index | Medium |
| [091](091-out-of-range-simd-extract-index.md) | Out-of-Range SIMD Extract Index | Medium |
| [092](092-unencoded-vsx-store-length.md) | Unencoded VSX Store Length | Medium |
| [093](093-any-comparisons-return-non-boolean-values.md) | any comparisons return non-boolean values | Medium |
| [094](094-unsanitized-argument-name-in-generated-identifiers.md) | Unsanitized Argument Name In Generated Identifiers | Medium |
| [095](095-safe-rcpc-store-dereferences-raw-pointer.md) | Safe RCpc Store Dereferences Raw Pointer | High |
| [096](096-safe-typed-rcpc-stores-erase-pointer-type.md) | Safe Typed RCpc Stores Erase Pointer Type | High |
| [097](097-unsupported-parameters-are-silently-omitted.md) | Unsupported Parameters Are Silently Omitted | Medium |
| [156](156-signed-immediate-lower-bound-off-by-one.md) | signed immediate lower bound off by one | Medium |
| [157](157-overflow-constructing-equal-iterator.md) | overflow constructing Equal iterator | Medium |
| [158](158-svld2-vnum-omits-vnum-offset-safety.md) | svld2_vnum omits vnum offset safety | Medium |
| [159](159-svld3-vnum-omits-vnum-offset-safety.md) | svld3_vnum omits vnum offset safety | Medium |
| [160](160-svst1-vnum-omits-vnum-offset-safety.md) | svst1_vnum omits vnum offset safety | Medium |
| [161](161-rot180-lane-parses-as-laneq.md) | rot180_lane Parses As laneq | Medium |
| [162](162-ord-inconsistent-with-eq-for-nvariantop.md) | Ord Inconsistent With Eq for NVariantOp | Medium |
| [163](163-invalid-neon-type-modifier-panics.md) | Invalid `neon_type` Modifier Panics | Medium |
| [173](173-cargo-argument-injection-via-environment.md) | cargo argument injection via environment | Medium |
| [197](197-rustflags-argument-injection-via-linker.md) | rustflags argument injection via linker | Medium |
| [198](198-generated-rust-injection-via-intrinsic-name.md) | Generated Rust Injection Via Intrinsic Name | Medium |

### std_detect

| # | Finding | Severity |
|---|---------|----------|
| [035](035-wrong-extended-cpuid-max-check.md) | Wrong Extended CPUID Max Check | Medium |
| [036](036-avx10-2-ignores-avxvnniint16-presence.md) | avx10_2 ignores avxvnniint16 presence | Medium |
| [037](037-unchecked-cpuid-0x24-query.md) | unchecked CPUID 0x24 query | Medium |
| [063](063-simd-extensions-ignore-simd-invariant.md) | SIMD Extensions Ignore SIMD Invariant | Medium |
| [122](122-file-descriptor-leak-on-allocation-panic.md) | File Descriptor Leak On Allocation Panic | Low |
| [123](123-interrupted-reads-are-not-retried.md) | Interrupted Reads Are Not Retried | Low |
| [154](154-unchecked-value-access-in-auxv-chunk.md) | Unchecked Value Access in auxv Chunk | Low |
| [155](155-unchecked-hwcap-value-access.md) | unchecked hwcap value access | Low |

### core

| # | Finding | Severity |
|---|---------|----------|
| [047](047-zero-denominator-in-duration-floor-division.md) | Zero Denominator in Duration Floor Division | Medium |
| [048](048-zero-denominator-in-duration-ceil-division.md) | Zero Denominator In Duration Ceil Division | Medium |
| [058](058-raw-slice-split-length-underflow.md) | Raw Slice Split Length Underflow | Medium |
| [098](098-non-static-typeids-cross-public-api-boundary.md) | Non-Static TypeIds Cross Public API Boundary | Medium |
| [099](099-unchecked-cached-power-index.md) | Unchecked Cached Power Index | Low |
| [100](100-incorrect-scratch-length-contract.md) | Incorrect Scratch Length Contract | Medium |
| [129](129-unchecked-div-exact-rejects-valid-negative-divisors.md) | unchecked_div_exact rejects valid negative divisors | Medium |
| [130](130-undocumented-nonaliasing-precondition.md) | Undocumented Nonaliasing Precondition | Medium |
| [178](178-zero-sized-elements-skipped-during-drain-drop.md) | Zero-Sized Elements Skipped During Drain Drop | Medium |
| [179](179-clamp-get-underflows-on-empty-slice.md) | Clamp get underflows on empty slice | Low |
| [180](180-inclusive-clamp-get-underflows-on-empty-slice.md) | Inclusive Clamp Get Underflows On Empty Slice | Low |
| [181](181-inclusive-rangeto-clamp-get-underflows-on-empty-slice.md) | Inclusive RangeTo Clamp `get` Underflows On Empty Slice | Low |
| [182](182-unchecked-isize-widening-arithmetic-overflows.md) | unchecked isize widening arithmetic overflows | Medium |
| [183](183-out-of-bounds-write-for-zero-sized-chunks.md) | Out-of-bounds write for zero-sized chunks | High |
| [184](184-zero-length-chunk-writes-out-of-bounds.md) | Zero-Length Chunk Writes Out Of Bounds | High |
| [185](185-panic-during-clone-drops-uninitialized-elements.md) | panic during clone drops uninitialized elements | High |
| [186](186-char-minimum-underflows-before-validation.md) | char minimum underflows before validation | Medium |

### compiler-builtins

| # | Finding | Severity |
|---|---------|----------|
| [001](001-unsafe-tar-extraction.md) | Unsafe Tar Extraction | Medium |
| [038](038-small-uefi-probes-corrupt-saved-frame-pointer.md) | small UEFI probes corrupt saved frame pointer | Medium |
| [045](045-unchecked-exponent-digit-accumulation.md) | unchecked exponent digit accumulation | Medium |
| [046](046-unchecked-mantissa-exponent-growth.md) | Unchecked Mantissa Exponent Growth | Low |
| [056](056-c-abi-uses-rust-reference-for-lgamma-r-sign-pointer.md) | C ABI uses Rust reference for lgamma_r sign pointer | Medium |
| [057](057-c-abi-uses-rust-reference-for-lgammaf-r-sign-pointer.md) | C ABI uses Rust reference for lgamma_r sign pointer | Medium |
| [064](064-unpinned-remote-git-dependencies.md) | Unpinned Remote Git Dependencies | Medium |
| [083](083-subword-rmw-writes-adjacent-bytes.md) | subword RMW writes adjacent bytes | High |
| [084](084-subword-compare-exchange-writes-adjacent-bytes.md) | subword compare-exchange writes adjacent bytes | High |
| [127](127-unverified-compiler-rt-download.md) | Unverified Compiler-RT Download | Medium |
| [175](175-unchecked-random-integer-pair-count-overflow.md) | Unchecked Random Integer Pair Count Overflow | Medium |
| [176](176-unchecked-mixed-integer-pair-count-overflow.md) | unchecked mixed integer pair count overflow | Medium |
| [177](177-sticky-bit-computed-from-overwritten-rlo.md) | sticky bit computed from overwritten rlo | Medium |

### test harness

| # | Finding | Severity |
|---|---------|----------|
| [115](115-poisoned-capture-mutex-panic.md) | Poisoned Capture Mutex Panic | Medium |
| [117](117-unescaped-test-name-xml-attributes.md) | Unescaped JUnit XML Attribute Values | Medium |
| [118](118-unescaped-failure-message-xml-attribute.md) | Unescaped Failure Message XML Attribute | Medium |
| [119](119-terminal-name-path-traversal.md) | Terminal Name Path Traversal | Medium |
| [164](164-unchecked-string-offset-panics.md) | Unchecked Terminfo String Offset Panics | Medium |
| [165](165-truncated-string-table-panics.md) | Truncated String Table Panics | Medium |
| [174](174-unescaped-ignore-message-in-discovery-json.md) | Unescaped Ignore Message In Discovery JSON | Medium |
| [199](199-unchecked-parameter-index-underflows.md) | unchecked parameter index underflows | Medium |
| [200](200-unchecked-division-by-zero.md) | unchecked division by zero | Medium |
| [201](201-unchecked-modulo-by-zero.md) | unchecked modulo by zero | Medium |

### proc_macro

| # | Finding | Severity |
|---|---------|----------|
| [003](003-byte-literal-accessor-checks-wrong-kind.md) | byte literal accessor checks wrong kind | Medium |
| [065](065-escaped-dollar-parsed-as-metavariable.md) | Escaped Dollar Parsed As Metavariable | Low |

### portable-simd

| # | Finding | Severity |
|---|---------|----------|
| [085](085-mutable-remote-helper-executed.md) | Mutable Remote Helper Executed | Medium |
| [131](131-unpinned-network-installer-executes-as-shell.md) | Unpinned Network Installer Executes As Shell | Medium |

### profiler_builtins

| # | Finding | Severity |
|---|---------|----------|
| [028](028-cargo-directive-injection-via-library-filename.md) | cargo directive injection via library filename | Medium |

### unwind

| # | Finding | Severity |
|---|---------|----------|
| [202](202-invalid-reference-from-instruction-pointer.md) | Invalid Reference From Instruction Pointer | High |

