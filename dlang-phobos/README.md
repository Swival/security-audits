# D Standard Library (Phobos) Audit Findings

Security audit of [Phobos](https://github.com/dlang/phobos), the standard library shipped with the D programming language. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 74** -- High: 40, Medium: 34

## Findings

### `std.experimental.allocator`

| # | Finding | Severity |
|---|---------|----------|
| [009](009-input-range-array-growth-leaves-caller-slice-stale-after-suc.md) | Input-range rollback invariant breaks after moved reallocation | High |
| [014](014-owning-region-remains-implicitly-copyable.md) | Owning `Region` remains implicitly copyable | High |
| [015](015-sharedregion-remains-implicitly-copyable.md) | `SharedRegion` double-frees backing storage on implicit copy | High |
| [028](028-contiguousfreelist-constructors-lose-ownership-of-allocated-.md) | `ContiguousFreeList` leaks parent-allocated support block | High |
| [034](034-deallocate-can-decommit-arbitrary-caller-chosen-pages.md) | `deallocate` can decommit arbitrary caller-chosen pages | High |
| [037](037-requested-size-rounding-can-overflow-to-a-too-small-allocati.md) | Requested-size rounding overflow yields overlapping allocation | High |
| [054](054-slice-start-rounding-can-move-past-buffer-end.md) | Slice-start rounding can move past buffer end | High |
| [057](057-reallocate-integer-overflow-shrinks-backing-request.md) | `reallocate` integer overflow shrinks backing request | High |
| [058](058-deallocate-trusts-masked-pointer-as-node-header.md) | `deallocate` trusts masked pointer as node header | High |
| [060](060-shared-type-flag-references-undefined-enum-member.md) | Shared type flag references undefined enum member | High |
| [061](061-allocator-fallback-returns-more-specific-policy-on-mismatch.md) | Allocator fallback returns previous extra allocator on mismatch | High |
| [065](065-failed-reallocate-drops-allocation-from-scope-tracking.md) | Failed `reallocate` corrupts scoped allocation metadata | High |
| [066](066-deallocate-unlinks-before-parent-failure-causing-stale-live-.md) | `ScopedAllocator` unlink-before-free orphans live allocation | High |
| [077](077-size-based-deallocate-can-free-through-wrong-allocator.md) | Size-based `deallocate` can free through wrong allocator | High |
| [080](080-deallocate-forwards-slices-to-bucket-chosen-by-caller-length.md) | `Bucketizer.deallocate` misroutes forged slices across buckets | High |
| [016](016-sbrkregion-state-stays-stale-after-deallocateall.md) | `SbrkRegion` stale state after `deallocateAll` | Medium |
| [029](029-sharedfreelist-deallocate-writes-through-null-pointer-for-nu.md) | `SharedFreeList` null deallocation crashes via null write | Medium |
| [035](035-owns-upper-bound-check-is-tautological.md) | `owns` upper-bound check is tautological | Medium |
| [051](051-clear-leaks-duplicate-sibling-blocks.md) | `free_tree.clear` leaks duplicate sibling blocks | Medium |
| [052](052-rounding-helper-overflows-and-returns-undersized-size.md) | Rounding helper overflows to undersized allocation size | Medium |
| [053](053-division-round-up-can-wrap-before-division.md) | Division round-up overflows to zero before division | Medium |
| [059](059-cross-allocator-move-can-leak-old-allocation.md) | Cross-allocator move can leak old allocation | Medium |
| [068](068-deallocateall-leaves-slack-accounting-stale.md) | `deallocateAll` leaves slack accounting stale | Medium |
| [078](078-ownership-checks-trust-slice-length-over-allocator-provenanc.md) | `Segregator` ownership checks trust slice length over provenance | Medium |
| [079](079-expand-threshold-check-can-overflow-and-misroute-allocator.md) | `Segregator.expand` overflow misroutes allocator | Medium |
| [081](081-ownership-check-trusts-caller-provided-slice-length.md) | `Bucketizer` ownership check uses caller-controlled length | Medium |
| [082](082-expand-size-addition-can-wrap-before-quantization.md) | `Quantizer.expand` size addition can wrap before quantization | Medium |

### Ranges, algorithms, and arrays

| # | Finding | Severity |
|---|---------|----------|
| [007](007-lazycache-returns-stale-back-after-front-pop.md) | `lazyCache` returns stale `back` after `popFront` | High |
| [008](008-lazycache-returns-stale-front-after-back-pop.md) | `lazyCache` returns stale `front` after `popBack` | High |
| [018](018-generator-stores-pointer-to-arbitrary-ref-return.md) | `Generator` stores pointer to arbitrary ref return | High |
| [019](019-static-array-cycle-can-outlive-source-array.md) | Static-array `cycle` can outlive source array | High |
| [020](020-refrange-save-and-slice-leak-heap-allocations.md) | `RefRange.save`/slice drops owned saved ranges without destruction | Medium |
| [021](021-replaceslice-dereferences-empty-slice-pointers.md) | `replaceSlice` dereferences empty slice pointers | Medium |

### Containers and buffers

| # | Finding | Severity |
|---|---------|----------|
| [062](062-insertbefore-bitwise-moves-non-trivial-elements.md) | `Array.insertBefore` bitwise-moves non-trivial elements | High |
| [063](063-reserve-bitwise-reallocates-destructible-elements.md) | `Array.reserve` bitwise-reallocates destructible elements | High |
| [064](064-data-exposes-mutable-slice-that-dangles-after-reallocation.md) | `Array.data()` mutable slice can dangle after reallocation | Medium |
| [070](070-indexing-and-slicing-permit-reads-beyond-initialized-length.md) | `ScopeBuffer` indexing and slicing read beyond initialized length | Medium |
| [072](072-misaligned-typed-writes-can-perform-invalid-stores.md) | `OutBuffer` misaligned typed writes can perform invalid stores | Medium |
| [073](073-other-typed-write-overloads-repeat-unchecked-misaligned-stor.md) | `OutBuffer` other typed write overloads repeat unchecked misaligned stores | Medium |

### BigInt, numerics, and math

| # | Finding | Severity |
|---|---------|----------|
| [043](043-increment-helper-writes-through-empty-slice.md) | `biguintx86` increment helper writes through empty slice | High |
| [044](044-shift-left-helpers-read-past-empty-source.md) | `biguintx86` shift-left helpers read past empty source | High |
| [048](048-divmod-omits-bigint-zero-divisor-check.md) | `divMod` omits BigInt zero-divisor check | Medium |
| [049](049-powmod-accepts-zero-modulus.md) | `BigInt.powmod` accepts zero modulus | Medium |
| [023](023-constructor-leaks-kernel-buffer-on-object-destruction.md) | `GapWeightedSimilarityIncremental` leaks kernel buffer on destruction | Medium |
| [084](084-polyimplbase-indexes-empty-coefficient-slice-in-trusted-code.md) | `polyImplBase` indexes empty coefficient slice in trusted code | Medium |

### Lifetimes and references

| # | Finding | Severity |
|---|---------|----------|
| [012](012-saferefcounted-borrow-can-return-dangling-payload-reference.md) | `SafeRefCounted.borrow` can return dangling payload reference | High |
| [017](017-todelegate-can-return-delegate-to-dead-stack-object.md) | `toDelegate` returns delegates with dangling stack context | High |
| [013](013-nullableref-dereferences-external-pointer-without-lifetime-e.md) | `NullableRef` allows `@safe` dangling-pointer dereference | Medium |

### Format scanning

| # | Finding | Severity |
|---|---------|----------|
| [038](038-raw-read-indexes-past-end-of-string-input.md) | Raw `%r` read indexes past end of narrow string input | High |
| [039](039-character-unformat-dereferences-empty-input.md) | Character unformat dereferences empty input | High |
| [040](040-skipdata-reads-front-on-empty-input.md) | `skipData` reads front on empty input | Medium |

### I/O and memory-mapped files

| # | Finding | Severity |
|---|---------|----------|
| [005](005-lockingtextreader-destructor-dereferences-null-after-eof-det.md) | `LockingTextReader` destructor null-dereferences closed file handle | High |
| [024](024-empty-slice-underflows-end-index-before-mapping.md) | `MmFile` empty slice remaps due to unsigned end-index underflow | High |
| [025](025-posix-file-growth-ignores-syscall-failures.md) | POSIX `MmFile` growth ignores syscall failures | Medium |

### Network and protocols

| # | Finding | Severity |
|---|---------|----------|
| [003](003-ftp-delete-command-injection-via-unsanitized-path.md) | FTP delete command injection in `del!FTP` | High |
| [006](006-unixaddress-path-underflows-on-short-os-reported-lengths.md) | `UnixAddress.path` underflows on short OS-reported lengths | High |
| [004](004-smtp-recipient-list-leaks-on-every-mailto-call.md) | SMTP recipient list leaks on every `mailTo` call | Medium |

### Time and timezone

| # | Finding | Severity |
|---|---------|----------|
| [041](041-timezone-name-escapes-database-directory.md) | Timezone name escapes database directory | High |
| [042](042-unchecked-abbreviation-index-slices-parsed-tzfile-buffer.md) | Unchecked TZif abbreviation index reads beyond abbreviation table | High |

### Zip

| # | Finding | Severity |
|---|---------|----------|
| [074](074-central-directory-offset-read-before-validation.md) | Central directory offset dereferenced before validation | High |
| [075](075-directory-header-slice-lacks-bounds-check.md) | Directory header slice lacks bounds check | High |
| [076](076-expand-trusts-local-header-sizes-for-decompression.md) | `expand` accepts forged local ZIP sizes for decompression | Medium |

### Base64

| # | Finding | Severity |
|---|---------|----------|
| [031](031-block-decode-silently-truncates-malformed-interior-padding.md) | Block decoder accepts invalid interior padding | Medium |
| [032](032-chunked-decoder-drops-data-after-early-padding-boundary.md) | Chunked decoder truncates trailing data after split padded quartet | Medium |

### JSON

| # | Finding | Severity |
|---|---------|----------|
| [046](046-safe-object-lookup-returns-alias-through-copied-aa.md) | Safe ordered-object lookup returns detached alias | High |
| [047](047-hash-violates-equality-for-numerically-equal-values.md) | Hash mismatches equality for integral float JSON numbers | Medium |

### Bitmanip

| # | Finding | Severity |
|---|---------|----------|
| [050](050-raw-void-constructor-permits-misaligned-size-t-access.md) | Raw `void[]` `BitArray` constructor permits misaligned `size_t` access | Medium |
| [086](086-flip-pos-writes-without-bounds-checking.md) | `BitArray.flip(pos)` lacks bounds validation | Medium |

### Windows

| # | Finding | Severity |
|---|---------|----------|
| [026](026-reg-sz-writes-omit-required-terminating-null.md) | `REG_SZ` writes omit required terminating null | High |
| [083](083-racy-lazy-initialization-of-dll-globals.md) | Racy lazy initialization of `advapi32` DLL globals | High |
| [027](027-string-value-reads-assert-on-valid-zero-length-registry-stri.md) | Zero-length registry strings trigger assertion | Medium |

### Regex

| # | Finding | Severity |
|---|---------|----------|
| [022](022-factory-refcount-updates-are-non-atomic.md) | `MatcherFactory` refcount updates are non-atomic | High |

### Random and entropy

| # | Finding | Severity |
|---|---------|----------|
| [011](011-chunked-getentropy-call-overruns-buffers-above-256-bytes.md) | Chunked `getentropy` loop uses the full buffer and breaks requests above 256 bytes | High |

### Parallelism

| # | Finding | Severity |
|---|---------|----------|
| [010](010-workerlocalstoragerange-slice-drops-base-offset.md) | `WorkerLocalStorageRange` slice drops consumed base offset | Medium |
