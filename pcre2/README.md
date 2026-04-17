# PCRE2 Audit Findings

Security audit of the PCRE2 library, covering serialization, the POSIX compatibility wrapper, and the test harness. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 5** -- High: 2, Medium: 3

## Findings

### Serialization

| # | Finding | Severity |
|---|---------|----------|
| [001](001-load-shifts-eof-into-serialized-size.md) | `#load` short-file EOF corrupts serialized size | Medium |
| [004](004-serialized-code-count-query-overreads-short-buffers.md) | Serialized code count query overreads short buffers | Medium |

### POSIX API wrapper

| # | Finding | Severity |
|---|---------|----------|
| [006](006-reg-startend-accepts-unchecked-negative-or-reversed-offsets.md) | REG_STARTEND negative offsets reach out-of-bounds subject memory | High |
| [007](007-regfree-leaves-dangling-internal-pointers.md) | regfree leaves dangling internal pointers | Medium |

### Test harness

| # | Finding | Severity |
|---|---------|----------|
| [002](002-32-bit-conversion-allocation-can-overflow.md) | 32-bit conversion allocation can overflow | High |
