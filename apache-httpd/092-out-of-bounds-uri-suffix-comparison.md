# out-of-bounds URI suffix comparison

## Classification

Memory safety; high severity; request-triggerable out-of-bounds read.

## Affected Locations

`modules/mappers/mod_speling.c:252`

## Summary

`mod_speling` compares `postgood` against a suffix of `r->uri` by computing `r->uri + (urlen - pglen)`. When `pglen > urlen`, the subtraction is negative and the pointer is moved before the start of the URI buffer. The subsequent `strcmp` performs an out-of-bounds read.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `CheckSpelling` is enabled.
- The request maps to a nonexistent file, leaving `r->finfo.filetype = APR_NOFILE`.
- The request has path info such that `postgood = bad + r->path_info` is longer than `r->uri`.
- The request reaches `check_speling`.

## Proof

The vulnerable code computes:

```c
urlen = strlen(r->uri);
pglen = strlen(postgood);

if (strcmp(postgood, r->uri + (urlen - pglen))) {
    return DECLINED;
}
```

A reachable configuration is:

```apache
Alias /s /tmp/abcdefghijklmnop

<Directory /tmp>
    CheckSpelling On
</Directory>
```

With `/tmp` existing and `/tmp/abcdefghijklmnop` nonexistent, a request for `/s/p` reaches `check_speling` with values equivalent to:

- `r->uri = "/s/p"`; `urlen = 4`
- `r->filename = "/tmp/abcdefghijklmnop"`
- `r->path_info = "/p"`
- `bad = "abcdefghijklmnop"`
- `postgood = "abcdefghijklmnop/p"`; `pglen = 18`

Therefore `urlen - pglen == -14`, so the expression evaluates a pointer equivalent to `r->uri - 14`. `strcmp(postgood, r->uri - 14)` reads before the URI buffer. An ASan harness confirms a heap-buffer-overflow for the same operation when `pglen > urlen`.

## Why This Is A Real Bug

`r->uri`, `r->filename`, and `r->path_info` are derived from request-controlled routing state and can reach `check_speling` under normal server configuration. The code assumes `postgood` is no longer than `r->uri` but does not validate that invariant before pointer arithmetic. In C, forming and dereferencing a pointer before the object is undefined behavior and can cause a crash or denial of service depending on allocator layout.

## Fix Requirement

Before computing or using `r->uri + (urlen - pglen)`, reject the request when `pglen > urlen`.

## Patch Rationale

The patch adds a length guard to the existing suffix consistency check:

```c
if (pglen > urlen || strcmp(postgood, r->uri + (urlen - pglen))) {
    return DECLINED;
}
```

Because `||` short-circuits in C, `strcmp` is not evaluated when `pglen > urlen`. This preserves the existing behavior for valid suffix comparisons while preventing underflow in the pointer offset.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mappers/mod_speling.c b/modules/mappers/mod_speling.c
index 2ed65eb..e71eb04 100644
--- a/modules/mappers/mod_speling.c
+++ b/modules/mappers/mod_speling.c
@@ -256,7 +256,7 @@ static int check_speling(request_rec *r)
     pglen = strlen(postgood);
 
     /* Check to see if the URL pieces add up */
-    if (strcmp(postgood, r->uri + (urlen - pglen))) {
+    if (pglen > urlen || strcmp(postgood, r->uri + (urlen - pglen))) {
         return DECLINED;
     }
```