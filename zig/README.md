# Security audit — zig @ 3f1dead2fc (verified)

## Run

- run id: `fd8c25cc`
- audited commit: `3f1dead2fc5922b588fbfb108f421ca957d6934a`
- verified against: master `2faf8debf1` (the audited commit is an ancestor; none of the
  intervening changes invalidate a finding)
- scope: `lib/std`, `lib/c`

## Verification

Every proposed finding was re-checked against the current source: the vulnerable code was located
and quoted, the technical claim reproduced or proven by inspection, the trust boundary judged under
a realistic threat model, and each patch confirmed to apply cleanly (`git apply --check`) and to be
logically correct. Several patch files that shipped with corrupt hunk headers or truncated trailing
context were regenerated from source; the crypto fixes (Ascon streaming, XSalsa20Poly1305 framing,
ZON cleanup) were additionally validated with runtime tests.

- proposed: 60
- **verified valid: 50**
- removed (out of threat model or false positive): 10

The 50 survivors were merged into the standing audit sets at
`~/src/swival-audits/zig-stdlib` (lib/std) and `~/src/swival-audits/zig-ziglibc` (lib/c).

## Verified findings

| # | severity | title | merged into |
|---|----------|-------|-------------|
| 002 | Critical | WASI Dir.access fails open for execute permission | stdlib 097 |
| 003 | Medium | Long IPv6 scope name overflows parser index | stdlib 098 |
| 004 | Medium | HTTPS proxy CONNECT rejection downgrades requests to proxy plaintext | stdlib 099 |
| 005 | Medium | Redirect userinfo overflows fixed Basic auth buffer | stdlib 100 |
| 006 | Medium | MSG_TRUNC receive length slices past buffer (Uring + Threaded) | stdlib 101 |
| 007 | High | LD_LIBRARY_PATH honored in capability-elevated ElfDynLib loads | stdlib 102 |
| 008 | Medium | Zero-sized Mach-O load commands stall iteration | stdlib 103 |
| 009 | Medium | Ignored unknown fields break ZON error cleanup | stdlib 104 |
| 010 | Medium | Malformed ELF program header offset panics buffer iterator | stdlib 105 |
| 011 | Medium | Malformed ELF dynamic section offset panics buffer iterator | stdlib 106 |
| 012 | Medium | Content-Length and Transfer-Encoding accepted together | stdlib 107 |
| 013 | Medium | TLS 1.2 short record underflows decrypted length | **duplicate → stdlib 030** |
| 014 | Medium | TLS 1.3 empty handshake record is indexed unchecked | stdlib 108 |
| 017 | Medium | u128 float-form integer overflows intermediate i128 conversion | stdlib 109 |
| 020 | High | AsconHash256 streaming update applies padding per chunk | stdlib 110 |
| 021 | High | Block-aligned Ascon-XOF128 squeeze repeats output | stdlib 111 |
| 022 | High | Block-aligned Ascon-CXOF128 squeeze repeats output | stdlib 112 |
| 023 | Medium | Unbounded bcrypt cost enables verification DoS | stdlib 113 |
| 024 | High | LZMA circular buffer wrap appends past backing capacity | stdlib 114 |
| 025 | High | ECDSA short DER integer sign and padding accepted | stdlib 115 |
| 026 | Critical | XSalsa20Poly1305 MAC lacks AD boundary separation | stdlib 116 |
| 028 | Medium | Oversized CCM ciphertext aborts verification | stdlib 117 |
| 029 | Low | AES-OCB decrypt authenticates overwritten associated data | stdlib 118 |
| 030 | Medium | Unchecked AES-SIV AD component count causes panic | stdlib 119 |
| 031 | Low | Malformed Mach-O symtab string table panics loader | stdlib 120 |
| 032 | Low | Malformed Mach-O symbol string index panics loader | stdlib 121 |
| 033 | Medium | zstd checksum verification panics on attacker data | stdlib 122 |
| 034 | Medium | Zero-length BIT STRING causes out-of-bounds read | stdlib 123 |
| 035 | High | GeneralizedTime accepts missing Z terminator | stdlib 124 |
| 036 | High | DER decode accepts trailing bytes when assertions are disabled | stdlib 125 |
| 037 | High | Uncompressed infinity bypasses P-384 point validation | stdlib 126 |
| 038 | High | Uncompressed SEC1 identity is accepted | stdlib 127 |
| 039 | High | Duplicate parameters satisfy required PHC fields | stdlib 128 |
| 043 | High | Secret exponent enters public variable-time path | stdlib 129 |
| 044 | Medium | Oversized DW_AT_addr_base panics before bounds validation | stdlib 130 |
| 045 | High | XZ block checksums are ignored | **duplicate → stdlib 077** |
| 046 | Critical | Edwards25519 order-two torsion passes subgroup check | stdlib 131 |
| 047 | High | Non-shortest DER long-form lengths accepted | stdlib 132 |
| 048 | High | Optional DER values suppress validation errors | stdlib 133 |
| 049 | High | Explicit field wrapper length is not enforced | stdlib 134 |
| 052 | Medium | HeadParser SIMD path misses LF-only header terminators | stdlib 135 |
| 053 | Low | number_literal leading exponent period underflows index | stdlib 136 |
| 054 | Medium | Windows drive-qualified zip paths bypass destination root | stdlib 137 |
| 055 | Low | DWARF line table lookup underflows before first row | stdlib 138 |
| 056 | High | mprotect wrapper truncates unaligned protection ranges | **duplicate → ziglibc 011** |
| 057 | Medium | Unauthenticated AES-GCM-SIV tag can overflow CTR counter | stdlib 139 |
| 059 | High | Non-hex letters accepted in chunk sizes | stdlib 140 |
| 060 | High | Empty chunk size accepted | stdlib 141 |
| 061 | High | Malformed chunk extension delimiter accepted | stdlib 142 |
| 062 | Medium | Zero-operand abbreviation panics record decoding | **duplicate → stdlib 096** |

## Removed during verification

Out of the realistic threat model — `lib/std/debug/*` self-debug paths (a process symbolizing or
unwinding *itself* from its *own* debug info, where the attacker would already control the binary):

- **015** — zero symtab entry size divides by zero (`debug/ElfFile` `searchSymtab`, self-info only)
- **016** — unchecked symbol name offset slices past strtab (same self-only `searchSymtab` path)
- **040** — oversized FDE count overflows table length (`debug/Dwarf/Unwind`, self-unwinder only)
- **041** — relative symbol offsets checked against absolute pointers (`debug/Pdb`, Windows self-info only)
- **042** — file checksum index lacks bounds check (`debug/Pdb`, Windows self-info only)
- **050** — DWARF expression dereferences process addresses (`debug/Dwarf/expression`, self-unwinder reads its own memory)
- **051** — truncated debug_addr entry panics expression evaluation (self-unwinder context never populates debug_addr)

Other trust boundaries that do not exist:

- **018** — growing file injects extra tar records: this is the tar *encoder* (archive creation),
  not decoding attacker input.
- **027** — error bundle lengths allocate before body validation: trusted build-runner↔compiler IPC.

False positive:

- **058** — "CTR counter wraps and reuses keystream": the public `ctr()` uses a full 128-bit
  counter, so wrapping is physically unreachable; AES-GCM-SIV wraps within bounds by RFC 8452
  design. The reproduction used an artificial 1-byte counter (caller misuse). Its `debug.assert`
  patch is a no-op in release builds, contradicts finding 057, and breaks GCM-SIV. Finding 057 is
  the correct and sufficient fix for the only real issue (overflow panic on a forged tag).

## How to read this directory

Each finding has a paired `NNN-<slug>.md` (the report) and `NNN-<slug>.patch` (the fix as a unified
diff against current master). Patches for 059/060/061 all touch `ChunkParser.zig` `.head_size` and
must be reconciled by hand if applied together; every patch applies cleanly on its own.
