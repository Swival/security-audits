# Zig ziglibc Audit Findings

Security audit of ziglibc, the Zig standard library's C compatibility layer. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 9** -- High: 4, Medium: 5

## Findings

### Memory allocation

| # | Finding | Severity |
|---|---------|----------|
| [001](001-malloc-integer-overflow.md) | malloc integer overflow | High |
| [003](003-posix-memalign-missing-alignment-validation.md) | posix_memalign missing alignment validation | Medium |

### C library shims

| # | Finding | Severity |
|---|---------|----------|
| [001](001-signed-minimum-overflows-in-abs-shims.md) | Signed minimum overflows in abs shims | Medium |
| [002](002-memccpy-omits-matched-byte-and-never-returns-null.md) | memccpy omits matched byte and never returns NULL | High |
| [003](003-strtok-r-leaves-save-state-stale-when-input-is-all-delimiter.md) | strtok_r leaves save state stale when input is all delimiter | Medium |
| [004](004-lrint-undefined-behavior-on-nan-inf-out-of-range-input.md) | lrint undefined behavior on NaN/Inf/out-of-range input | High |
| [012](012-wcsnlen-slices-with-maxint-usize-on-sentinel-terminated-poin.md) | wcsnlen slices with maxInt(usize) on sentinel-terminated pointer | Medium |

### Linux syscall layer

| # | Finding | Severity |
|---|---------|----------|
| [001](001-getgroupslinux-intcast-of-negative-size-causes-panic.md) | getgroupsLinux @intCast of negative size causes panic | Medium |
| [011](011-mprotectlinux-aligns-len-without-accounting-for-addr-alignme.md) | mprotectLinux aligns len without accounting for addr alignment delta | High |
