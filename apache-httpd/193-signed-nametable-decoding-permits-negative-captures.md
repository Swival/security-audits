# Signed Nametable Decoding Permits Negative Captures

## Classification

Memory safety; medium severity.

## Affected Locations

`server/util_pcre.c:521`

## Summary

`ap_regname()` decodes PCRE/PCRE2 nametable capture numbers from two bytes using signed `char` operands. On platforms where `char` is signed, a high-bit nametable byte can sign-extend during integer promotion, producing a negative `capture` index. The growth loop is then skipped and the subsequent assignment indexes before `names->elts`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Platform uses signed `char`.
- A compiled regex nametable contains a capture number with the high bit set.
- Callers enumerate regex names through `ap_regname()`.

## Proof

PCRE and PCRE2 expose the compiled regex nametable through `PCRE_INFO_NAMETABLE` / `PCRE2_INFO_NAMETABLE`. Each entry begins with a two-byte capture number.

The vulnerable code decodes that number as:

```c
int capture = ((offset[0] << 8) + offset[1]);
```

Because `offset` is a `const char *`, `offset[0]` and `offset[1]` are signed `char` values on signed-char platforms. If the low byte is `0x80`, then `offset[1]` promotes to `-128`, so bytes `00 80` decode as `capture = -128`.

The loop:

```c
while (names->nelts <= capture) {
    apr_array_push(names);
}
```

does not execute for a negative value. The later assignment writes through the negative index:

```c
((char **) names->elts)[capture] = ...
```

The same issue exists in the non-prefix branch:

```c
((const char **)names->elts)[capture] = offset + 2;
```

A PCRE2 harness using the same decode/index logic reproduced the condition with a regex containing 128 named optional groups. The final nametable entry contained bytes `00 80`, decoded to `capture = -128`, and placing the array at a guard page caused a crash on the negative-index write.

Reachability exists in committed code because configuration regex containers compile regexes with `ap_pregcomp()` and immediately enumerate names with `ap_regname()`, including:

- `server/core.c:2527`
- `server/core.c:2608`
- `server/core.c:2695`
- `modules/proxy/mod_proxy.c:2887`

A configuration regex such as `LocationMatch`, `DirectoryMatch`, `FilesMatch`, or `ProxyMatch` with at least 128 named captures reaches the vulnerable path during configuration parsing.

## Why This Is A Real Bug

The nametable format stores capture numbers as unsigned bytes, but the implementation decodes them through signed `char`. This is implementation-dependent and unsafe on signed-char platforms. A valid nametable value with the high bit set can become a negative array index, causing an out-of-bounds write before APR array storage.

## Fix Requirement

Decode nametable bytes as unsigned values before shifting or adding them.

## Patch Rationale

Casting both nametable bytes to `unsigned char` prevents sign extension during integer promotion. The decoded capture number remains in the expected non-negative range, so the APR array growth loop runs before the indexed assignment.

## Residual Risk

None

## Patch

```diff
diff --git a/server/util_pcre.c b/server/util_pcre.c
index 0a9dc50..5849e7c 100644
--- a/server/util_pcre.c
+++ b/server/util_pcre.c
@@ -521,7 +521,7 @@ AP_DECLARE(int) ap_regname(const ap_regex_t *preg,
 
     for (i = 0; i < namecount; i++) {
         const char *offset = nametable + i * nameentrysize;
-        int capture = ((offset[0] << 8) + offset[1]);
+        int capture = (((unsigned char)offset[0] << 8) + (unsigned char)offset[1]);
         while (names->nelts <= capture) {
             apr_array_push(names);
         }
```