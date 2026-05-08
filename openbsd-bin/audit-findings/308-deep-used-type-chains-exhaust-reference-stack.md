# Deep Used Type Chains Exhaust Reference Stack

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.bin/ctfconv/parse.c:306`

## Summary

`ctfconv` recursively marks reachable DWARF-derived internal types from used object and function roots. An attacker-controlled object file can encode a very deep acyclic chain of `DW_AT_type` references reachable from a named global variable. Processing that object causes `it_reference()` to consume one C stack frame per referenced type and can terminate `ctfconv` via stack exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer analysis.

## Preconditions

- `ctfconv` processes an attacker-supplied object file.
- The object file contains DWARF data.
- The DWARF data contains a used root, such as a named global `DW_TAG_variable`.
- The used root references an attacker-chosen deep chain of types.

## Proof

The reproduced path is:

- `parse_variable()` converts a named global `DW_TAG_variable` with location data into an `ITF_OBJ` root.
- `cu_resolve()` resolves each `DW_AT_type` reference by CU-relative offset into `it_refp`.
- A crafted object can therefore form an acyclic chain: `object -> type1 -> type2 -> ... -> base`.
- `cu_reference()` calls `it_reference()` for each `ITF_OBJ` or `ITF_FUNC`.
- The original `it_reference()` recursively follows `it->it_refp` and each member `im->im_refp` without a depth bound.
- `ITF_USED` prevents cycles and duplicate visits, but does not limit a long acyclic chain.
- A sufficiently deep chain consumes one process stack frame per type and can terminate `ctfconv`.

Relevant source evidence:

- `usr.bin/ctfconv/parse.c:293` checks only for `NULL` and `ITF_USED`.
- `usr.bin/ctfconv/parse.c:298` marks the current type as used.
- `usr.bin/ctfconv/parse.c:306` recursively follows `it->it_refp`.
- `usr.bin/ctfconv/parse.c:523` calls `it_reference()` for used objects and functions.

## Why This Is A Real Bug

DWARF contents are attacker-controlled when `ctfconv` is run on an untrusted object file. The parser accepts and resolves reference chains from the object file into internal `itype` nodes before marking used types. The marking phase originally used unbounded recursion over those resolved references, so valid-looking acyclic input can drive stack consumption proportional to attacker-chosen type-chain depth. This is sufficient for a local denial of service against the `ctfconv` process.

## Fix Requirement

Replace the recursive traversal in `it_reference()` with an iterative traversal using an explicit heap-allocated stack and preserve visited checks with `ITF_USED`.

## Patch Rationale

The patch removes input-depth-dependent C stack growth by storing pending types in an explicit heap stack. It marks a type as `ITF_USED` before pushing it, which preserves the previous cycle and duplicate-visit behavior while preventing the same node from being pushed repeatedly. The traversal still follows both direct type references and member references, so reachable-type marking semantics are retained.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ctfconv/parse.c b/usr.bin/ctfconv/parse.c
index ef483f9..f742d8b 100644
--- a/usr.bin/ctfconv/parse.c
+++ b/usr.bin/ctfconv/parse.c
@@ -289,15 +289,44 @@ void
 it_reference(struct itype *it)
 {
 	struct imember *im;
+	struct itstack {
+		struct itype	*is_it;
+		struct itstack	*is_next;
+	} *is, *next;
 
 	if (it == NULL || it->it_flags & ITF_USED)
 		return;
 
+	is = xmalloc(sizeof(*is));
 	it->it_flags |= ITF_USED;
+	is->is_it = it;
+	is->is_next = NULL;
 
-	it_reference(it->it_refp);
-	TAILQ_FOREACH(im, &it->it_members, im_next)
-		it_reference(im->im_refp);
+	while (is != NULL) {
+		it = is->is_it;
+		next = is->is_next;
+		free(is);
+		is = next;
+
+		if (it->it_refp != NULL &&
+		    !(it->it_refp->it_flags & ITF_USED)) {
+			next = xmalloc(sizeof(*next));
+			it->it_refp->it_flags |= ITF_USED;
+			next->is_it = it->it_refp;
+			next->is_next = is;
+			is = next;
+		}
+		TAILQ_FOREACH(im, &it->it_members, im_next) {
+			if (im->im_refp == NULL ||
+			    im->im_refp->it_flags & ITF_USED)
+				continue;
+			next = xmalloc(sizeof(*next));
+			im->im_refp->it_flags |= ITF_USED;
+			next->is_it = im->im_refp;
+			next->is_next = is;
+			is = next;
+		}
+	}
 }
 
 void
```