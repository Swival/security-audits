# regfree leaves dangling internal pointers

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/pcre2posix.c:236`

## Summary
`pcre2_regfree()` frees `preg->re_match_data` and `preg->re_pcre2_code` but leaves both fields unchanged. Re-invoking `pcre2_regfree()` on the same `regex_t` reuses stale internal pointers, causing allocator-facing use-after-free and repeated free paths on already released objects.

## Provenance
- Verified from the provided finding and local reproduction evidence
- Scanner source: https://swival.dev

## Preconditions
- A caller invokes `pcre2_regfree()` more than once on the same `regex_t`

## Proof
- `pcre2_regcomp()` stores allocated state in `preg->re_match_data` and `preg->re_pcre2_code`
- `pcre2_regfree()` frees those members at `src/pcre2posix.c:236` but does not set them to `NULL`
- The reproduced PoC calls:
```c
pcre2_regcomp(&re, "a", 0);
pcre2_regfree(&re);
pcre2_regfree(&re);
```
- Under ASan, the second `pcre2_regfree()` crashes with `heap-use-after-free` in `pcre2_match_data_free_8` at `src/pcre2_match_data.c:101`, reached from `pcre2_regfree` in `src/pcre2posix.c:257`
- `pcre2_match_data_free()` dereferences the freed `match_data` object before final release, and `pcre2_code_free()` similarly dereferences `code` internals before freeing, so stale pointers are actively unsafe on reuse

## Why This Is A Real Bug
This is directly reachable through the public POSIX wrapper API with no memory corruption primitive needed beyond repeated valid-looking lifecycle calls on a retained `regex_t`. The bug is not theoretical: it reproduces reliably under ASan, and the freed pointers are dereferenced on the second call. Even if the first observed failure is use-after-free rather than a raw double-free, it arises from the same stale-pointer lifecycle flaw and can crash consumers.

## Fix Requirement
After each successful free in `pcre2_regfree()`, clear the corresponding field by assigning `NULL` to `preg->re_match_data` and `preg->re_pcre2_code`.

## Patch Rationale
Nulling the internal pointers immediately after free makes repeated `pcre2_regfree()` calls idempotent for these members. This matches the ownership model of `regex_t`, prevents stale-pointer reuse, and eliminates both the observed use-after-free on `re_match_data` and the subsequent re-free risk on `re_pcre2_code`.

## Residual Risk
None

## Patch
- `007-regfree-leaves-dangling-internal-pointers.patch` updates `pcre2_regfree()` in `src/pcre2posix.c` to set `preg->re_match_data = NULL` after `pcre2_match_data_free()` and `preg->re_pcre2_code = NULL` after `pcre2_code_free()`