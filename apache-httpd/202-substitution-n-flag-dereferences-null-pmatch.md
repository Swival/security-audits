# substitution n flag dereferences null pmatch

## Classification

Memory safety, high severity.

## Affected Locations

`server/util_regex.c:160`

`server/util_regex.c:167`

## Summary

`ap_rxplus_compile()` accepts the `n` flag for substitution expressions. The `n` flag sets `AP_REG_NOMEM`, which suppresses `nmatch` initialization and `pmatch` allocation. `ap_rxplus_exec()` still enters the substitution path and dereferences `rx->pmatch[0]`, causing a NULL pointer dereference for matching `s///n` patterns.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller compiles a substitution regex with the `n` flag and executes it on a string that matches the regex.

## Proof

`ap_rxplus_compile()` parses trailing flags and sets `AP_REG_NOMEM` for `n` at `server/util_regex.c:102`.

When `AP_REG_NOMEM` is set, `ap_rxplus_compile()` skips the block that initializes `ret->nmatch` and allocates `ret->pmatch` at `server/util_regex.c:117`.

Because `ret` is allocated with `apr_pcalloc()`, `ret->pmatch` remains `NULL`.

`ap_rxplus_exec()` executes the regex with `rx->nmatch == 0` and `rx->pmatch == NULL` at `server/util_regex.c:149`. Matching succeeds because zero-match execution is valid.

If `rx->subs` is set, the substitution path is entered. `ap_pregsub()` with `nmatch == 0` can return a duplicate of the replacement string, so execution continues.

The first crashing dereference is:

```c
startl = rx->pmatch[0].rm_so;
```

at `server/util_regex.c:160`.

For global substitutions, later execution can also reach `server/util_regex.c:167`.

## Why This Is A Real Bug

The substitution path requires whole-match offsets to splice the replacement into the original string. Those offsets are read from `rx->pmatch[0]`.

The `n` flag explicitly prevents match-vector allocation, leaving `rx->pmatch == NULL`. There is no guard before `rx->pmatch[0]` is accessed.

Therefore, a matching substitution expression using `n`, such as an `s///n` pattern, can crash the process through a deterministic NULL pointer dereference.

## Fix Requirement

Substitution regexes must not be allowed to run without match storage.

A valid fix must either:

- reject `n` for substitutions, or
- allocate at least the whole-match `pmatch[0]` entry whenever `rx->subs` is set.

## Patch Rationale

The patch rejects substitution expressions that also request `AP_REG_NOMEM`:

```c
if (ret->subs && (ret->flags & AP_REG_NOMEM)) {
    return NULL;
}
```

This enforces the invariant that compiled substitution regexes always have match storage available before `ap_rxplus_exec()` can dereference `rx->pmatch[0]`.

The check occurs after flag parsing and before regex compilation, so invalid `s///n` patterns fail during compilation rather than producing a runtime crash.

## Residual Risk

None

## Patch

```diff
diff --git a/server/util_regex.c b/server/util_regex.c
index 5405f8d..de99f0f 100644
--- a/server/util_regex.c
+++ b/server/util_regex.c
@@ -107,6 +107,9 @@ AP_DECLARE(ap_rxplus_t*) ap_rxplus_compile(apr_pool_t *pool,
         default: break; /* we should probably be stricter here */
         }
     }
+    if (ret->subs && (ret->flags & AP_REG_NOMEM)) {
+        return NULL;
+    }
     if (ap_regcomp(&ret->rx, rxstr, AP_REG_NO_DEFAULT | ret->flags) == 0) {
         apr_pool_cleanup_register(pool, &ret->rx, rxplus_cleanup,
                                   apr_pool_cleanup_null);
```