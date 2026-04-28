# out-of-bounds URI suffix comparison

## Classification

Memory safety; request-triggerable out-of-bounds read; severity high; confidence certain

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

## Practical Exploit Scenario

A site uses `mod_speling` with `CheckSpelling On` to forgive typos on user-facing URLs (a common ergonomic choice on community sites and documentation portals). The administrator also publishes content via `Alias` directives that point at deeply nested filesystem paths, for example:

```apache
Alias /s "/srv/uploads/long-customer-bucket-prefix-2026-q1-archive"

<Directory "/srv/uploads">
    CheckSpelling On
    Require all granted
</Directory>
```

An unauthenticated attacker discovers the alias and sends:

```http
GET /s/p HTTP/1.1
Host: example.test
```

The aliased file does not exist, so `mod_speling` is invoked. Internally `r->uri` is the short `/s/p` (4 bytes) while `postgood` becomes the alias basename joined with `path_info`, here `long-customer-bucket-prefix-2026-q1-archive/p` (45 bytes). The expression `r->uri + (urlen - pglen)` evaluates to a pointer 41 bytes *before* the URI buffer. `strcmp` then walks backward through whatever happens to live in the request pool: pool node headers, prior request strings, allocator metadata, or guard pages.

On hardened builds (ASan, FORTIFY, libc canaries, or pool guard pages) the read faults and kills the worker. The attacker scripts the request in a tight loop and exhausts every MPM child until the server stops accepting connections, all without any credentials, valid path knowledge, or large payload. On stock builds the read is silent but unstable: occasional false matches in `strcmp` change the spelling-correction outcome, occasional alignment-sensitive crashes still bring workers down, and any future hardening enables the DoS unconditionally. Because `Alias` paths longer than the request URI are extremely common on real servers (anything aliased into a deeply nested data directory satisfies the precondition), the trigger does not require a contrived configuration.

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