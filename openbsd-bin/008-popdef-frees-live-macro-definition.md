# popdef frees live macro definition

## Classification

Denial of service, medium severity.

## Affected Locations

`m4/look.c:202`

## Summary

`macro_popdef` directly frees the popped macro definition string even when that string is still referenced by an active macro expansion frame. This bypasses the existing `free_definition` deferral mechanism used by `macro_define`, allowing attacker-controlled m4 input to trigger a use-after-free and crash the `m4` process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- An attacker can supply an m4 input file.
- A macro definition string is live in `sstack` / `mstack` during `popdef`.
- `popdef` is invoked for the macro while its current definition is still being expanded.

## Proof

The bug was reproduced.

Execution flow:

- `main.c` pushes the current macro definition pointer with `pushdef(p)` before collecting arguments.
- `pushdef(p)` stores `macro_getdef(p)->defn` in `mstack[sp].sstr` and marks the stack entry as `STORAGE_MACRO` at `m4/mdef.h:200`.
- A nested `popdef(`f')` executes while the outer `f` expansion frame is still on the stack.
- `macro_popdef` removes `n->d`, then directly calls `free(r->defn)` at `m4/look.c:205`.
- After `popdef` returns, the outer `f` expansion still uses the freed definition through `argv[0]` in `expand_macro`.
- ASan reports a heap-use-after-free read at `m4/eval.c:528`, with the allocation freed from `m4/look.c:206`.

The existing safety mechanism is present but bypassed:

- `macro_define` calls `free_definition(n->d->defn)` at `m4/look.c:158`.
- `free_definition` checks `string_in_use` and defers freeing live macro strings at `m4/look.c:302`.
- `macro_popdef` used `free(r->defn)` directly instead of `free_definition(r->defn)`.

## Why This Is A Real Bug

This is a real memory-safety bug because `mstack[i].sstr` can retain a pointer to the popped definition while expansion is still in progress. Directly freeing that definition leaves the active expansion stack with a dangling pointer. Later expansion dereferences that pointer, producing a heap-use-after-free.

The behavior is attacker-triggerable through an m4 input file that defines or push-defines a macro and invokes `popdef` during that macro's expansion. The practical impact is denial of service through process abort/crash under memory-safety checking or hardened allocator behavior.

## Fix Requirement

`macro_popdef` must use the same live-definition-aware release path as `macro_define`.

Specifically, replace:

```c
free(r->defn);
```

with:

```c
free_definition(r->defn);
```

when `r->defn != null`.

## Patch Rationale

`free_definition` already implements the required ownership policy for macro definition strings:

- It first frees previously kept strings that are no longer live.
- It checks whether the target string is currently referenced by `sstack` / `mstack`.
- It defers freeing live strings by storing them in the `kept` array.
- It immediately frees strings that are not live.

Using `free_definition` in `macro_popdef` makes popped definitions follow the same lifetime rules as redefined definitions in `macro_define`, preventing active expansion frames from retaining dangling pointers.

## Residual Risk

None

## Patch

```diff
diff --git a/m4/look.c b/m4/look.c
index 3d23e80..adb72b4 100644
--- a/m4/look.c
+++ b/m4/look.c
@@ -203,7 +203,7 @@ macro_popdef(const char *name)
 		if (r != NULL) {
 			n->d = r->next;
 			if (r->defn != null)
-				free(r->defn);
+				free_definition(r->defn);
 			free(r);
 		}
 	}
```