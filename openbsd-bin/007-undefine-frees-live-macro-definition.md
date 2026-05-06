# undefine frees live macro definition

## Classification

Denial of service, medium severity.

## Affected Locations

`m4/look.c:189`

## Summary

`macro_undefine` directly frees macro definition strings even when those strings are still referenced by the active expansion stack. Attacker-controlled m4 input can undefine a macro while its definition is live, leaving `mstack` with a dangling pointer. Later expansion dereferences the freed string and can crash the m4 process.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `m4` processes attacker-controlled input.
- The input expands a macro and undefines the same live macro definition during that expansion.

## Proof

Minimal reproducer:

```m4
define(`foo', `A')
foo(undefine(`foo'))
```

Reachability and fault path:

- `main.c:398` creates the outer `foo` call frame.
- `mdef.h:200` stores `macro_getdef(p)->defn` in `mstack` with `STORAGE_MACRO`.
- Nested `undefine` reaches `expand_builtin` at `eval.c:370`.
- `expand_builtin` calls `macro_undefine` at `eval.c:376`.
- `macro_undefine` directly frees `r->defn` at `m4/look.c:189`.
- When the outer `foo` call completes, `main.c:462` calls `eval` with stale `argv[0]`.
- `expand_macro` dereferences the freed pointer at `eval.c:528`.

Runtime evidence from an ASan build reports:

- `heap-use-after-free` in `expand_macro` at `eval.c:528`.
- Freed by `macro_undefine` at `m4/look.c:189`.
- Allocated by `macro_define` at `m4/look.c:163`.

## Why This Is A Real Bug

The code already recognizes that macro definition strings can remain live during expansion. `free_definition` checks `string_in_use` against `sstack` and `mstack`; if a definition is still live, it defers freeing by retaining the pointer in `kept`.

`macro_define` uses this safe path when replacing a definition:

```c
if (n->d->defn != null)
	free_definition(n->d->defn);
```

`macro_undefine` does not use the same safe path. It calls `free` directly on non-null definitions, bypassing the liveness check and freeing memory still reachable from `mstack`.

This creates an attacker-triggered use-after-free and denial of service when untrusted m4 input is processed. The matching bug in `macro_popdef` is tracked separately.

## Fix Requirement

Use `free_definition` instead of direct `free` for non-null macro definition strings removed by `macro_undefine`. This preserves the existing deferred-free behavior for definitions that are still live on the expansion stack.

## Patch Rationale

The patch changes only the deallocation path for the macro definition string in `macro_undefine`. It does not alter lookup, stack manipulation, macro removal, or definition ownership.

`free_definition` is the established allocator-pairing helper for this exact lifetime case:

- If the definition is not live, it frees immediately.
- If the definition is live, it keeps the string until no expansion stack entry references it.
- It also opportunistically frees previously kept strings that are no longer live.

Applying the same helper in `macro_undefine` makes the undefine path honor the same lifetime invariant already used by `macro_define`.

## Residual Risk

None.

## Patch

```diff
diff --git a/m4/look.c b/m4/look.c
index 3d23e80..26acdc1 100644
--- a/m4/look.c
+++ b/m4/look.c
@@ -186,7 +186,7 @@ macro_undefine(const char *name)
 		for (r = n->d; r != NULL; r = r2) {
 			r2 = r->next;
 			if (r->defn != null)
-				free(r->defn);
+				free_definition(r->defn);
 			free(r);
 		}
 		n->d = NULL;
```
