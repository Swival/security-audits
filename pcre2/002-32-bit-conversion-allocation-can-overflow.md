# 32-bit conversion allocation can overflow

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/pcre2test_inc.h:370`
- `src/pcre2test_inc.h:507`
- `src/pcre2test_inc.h:508`
- `src/pcre2test_inc.h:521`
- `src/pcre2test_inc.h:544`

## Summary
On 32-bit builds, `to32()` computes the backing allocation as `4 * len + 4` in `PCRE2_SIZE` without overflow checking. For attacker-controlled pattern lengths near the tool's accepted upper bound, this wraps to a small allocation, after which the conversion loop writes one `uint32_t` per input byte plus a terminator, causing a heap overflow.

## Provenance
- Source: verified finding provided by user
- Reproduced: yes
- Scanner: https://swival.dev
- Patch: `002-32-bit-conversion-allocation-can-overflow.patch`

## Preconditions
- 32-bit build
- Attacker-controlled pattern input length near `SIZE_MAX / 4`
- Input reaches `process_pattern()` and is passed into `to32()`

## Proof
`process_pattern()` passes pattern byte length into `to32()`, which copies it into local `len` and checks whether `pbuffer32_size < 4 * len + 4` at `src/pcre2test_inc.h:370`. On 32-bit builds this multiplication occurs in `PCRE2_SIZE` and can wrap.

The reproduced path shows the converted length being used to size iteration bounds at `src/pcre2test_inc.h:507` and `src/pcre2test_inc.h:508`. In the non-UTF path, the function then writes one `uint32_t` per input byte at `src/pcre2test_inc.h:521` and appends a terminator at `src/pcre2test_inc.h:544`. If the allocation wrapped, these writes overrun `pbuffer32` by a large margin.

Reproduction also confirms exploitability within the program's nominally accepted pattern range: `MAX_PATTERN_SIZE == 1 << 30` at `src/pcre2_intmodedep.h:193`, and overflow begins at `1073741823`, so the bug triggers for inputs still inside the documented 32-bit pattern ceiling.

The broader claim about "name inputs" is not supported by the call sites. The only other `to32()` users are bounded name lookups in `copy_and_get()` at `src/pcre2test_inc.h:3660` and `src/pcre2test_inc.h:3744`, with `LENCPYGET == 64` at `src/pcre2test.c:643` and validating checks at `src/pcre2test_inc.h:1033` and `src/pcre2test_inc.h:1039`.

## Why This Is A Real Bug
The overflow is on the allocation size, not merely on a diagnostic or unused counter. The wrapped result directly controls heap allocation, and the subsequent conversion writes are proportional to the original unwrapped input length. That creates a concrete heap buffer overflow on a reachable path with attacker-controlled input size. The triggering length is also within the tool's own accepted 32-bit pattern limit, so this is not blocked by existing size policy.

## Fix Requirement
Reject lengths greater than `(PCRE2_SIZE_MAX - 4) / 4` before computing `4 * len + 4`, and only allocate after the checked bound guarantees the size expression cannot wrap.

## Patch Rationale
The patch adds a pre-allocation upper-bound check in `to32()` so the size calculation cannot overflow on 32-bit builds. This preserves existing behavior for valid inputs, fails safely for oversized patterns, and addresses the only reproduced attacker-controlled path without changing conversion semantics.

## Residual Risk
None

## Patch
```diff
--- a/src/pcre2test_inc.h
+++ b/src/pcre2test_inc.h
@@ -367,8 +367,14 @@ to32(PCRE2_SPTR p, PCRE2_SIZE *lenptr)
 uint32_t *pp;
 PCRE2_SIZE len = *lenptr;
 
-if (pbuffer32_size < 4*len + 4)
+if (len > (PCRE2_SIZE_MAX - 4)/4)
   {
+  fprintf(outfile, "** Pattern is too large to convert to 32-bit data\n");
+  exit(1);
+  }
+
+if (pbuffer32_size < 4*len + 4)
+  {
   pbuffer32_size = 4*len + 4;
   pbuffer32 = (uint32_t *)realloc(pbuffer32, CU2BYTES(pbuffer32_size));
   if (pbuffer32 == NULL)
```