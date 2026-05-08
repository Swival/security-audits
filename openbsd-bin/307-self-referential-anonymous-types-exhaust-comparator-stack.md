# Self-Referential Anonymous Types Exhaust Comparator Stack

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.bin/ctfconv/parse.c:366`

## Summary

`ctfconv` can exhaust its stack while processing attacker-controlled DWARF. Two used anonymous pointer DIEs whose `DW_AT_type` attributes point to themselves cause `it_cmp()` to recurse indefinitely during type-tree lookup in `cu_merge()`.

## Provenance

Verified from supplied source, reproduced execution path, and patch evidence. Finding originated from Swival Security Scanner: https://swival.dev

## Preconditions

`ctfconv` processes an attacker-controlled DWARF object file.

## Proof

`parse_refers()` creates anonymous pointer types with `ITF_UNRES` when `DW_AT_name` is absent and accepts attacker-controlled `DW_AT_type`.

`cu_resolve()` resolves the relative reference through `cuot`; when `DW_AT_type` points to the DIE itself, `it_refp` is set to the same `itype`.

`parse_variable()` creates `ITF_OBJ` entries when name, type, and block-form location are present, and `cu_reference()` marks referenced types `ITF_USED`.

During `cu_merge()`, the first used anonymous pointer is inserted into `itypet[it->it_type]`. The second used anonymous pointer reaches `RB_FIND()` on the same tree.

`it_cmp()` compares same-kind anonymous types by reference. For two self-referential anonymous pointers, both `it_refp` fields are non-NULL and point back to their own objects, so the recursive call compares the identical pair forever:

```c
return it_cmp(a->it_refp, b->it_refp);
```

This causes unbounded recursion, stack exhaustion, and termination during object processing.

## Why This Is A Real Bug

The comparator is used by red-black tree operations, so it must terminate and provide stable ordering. Attacker-controlled DWARF can construct cyclic anonymous type references. The existing comparator has no identity check or visited-pair detection before recursively comparing referenced types, so a valid reachable parser state produces non-termination.

The reproduced path confirms the issue reaches `RB_FIND()` in `cu_merge()` and recurses indefinitely through `it_cmp()`.

## Fix Requirement

Detect already-compared reference pairs before recursive `it_cmp()` calls and terminate comparison for repeated pairs.

## Patch Rationale

The patch introduces a small recursion context, `struct itcmp`, threaded through a new helper `it_cmp_recur()`.

Before comparing a pair, the helper checks whether the same `(a, b)` pair already exists in the active comparison stack. If so, it returns `0`, treating the cyclic pair as equivalent for comparator purposes.

Before recursing through `it_refp`, the current pair is pushed onto the stack:

```c
cur.itc_a = a;
cur.itc_b = b;
cur.itc_next = seen;
return it_cmp_recur(a->it_refp, b->it_refp, &cur);
```

The public `it_cmp()` wrapper preserves the existing comparator API used by `RB_GENERATE()` while adding cycle detection internally.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ctfconv/parse.c b/usr.bin/ctfconv/parse.c
index ef483f9..e40c4f6 100644
--- a/usr.bin/ctfconv/parse.c
+++ b/usr.bin/ctfconv/parse.c
@@ -317,12 +317,25 @@ it_free(struct itype *it)
 	pfree(&it_pool, it);
 }
 
+struct itcmp {
+	struct itype	*itc_a;
+	struct itype	*itc_b;
+	struct itcmp	*itc_next;
+};
+
 /*
  * Return 0 if ``a'' matches ``b''.
  */
-int
-it_cmp(struct itype *a, struct itype *b)
+static int
+it_cmp_recur(struct itype *a, struct itype *b, struct itcmp *seen)
 {
+	struct itcmp *itc, cur;
+
+	for (itc = seen; itc != NULL; itc = itc->itc_next) {
+		if (itc->itc_a == a && itc->itc_b == b)
+			return 0;
+	}
+
 	if (a->it_type > b->it_type)
 		return 1;
 	if (a->it_type < b->it_type)
@@ -357,8 +370,12 @@ it_cmp(struct itype *a, struct itype *b)
 		return (a->it_flags & ITF_ANON) ? -1 : 1;
 
 	/* Match by reference */
-	if ((a->it_refp != NULL) && (b->it_refp != NULL))
-		return it_cmp(a->it_refp, b->it_refp);
+	if ((a->it_refp != NULL) && (b->it_refp != NULL)) {
+		cur.itc_a = a;
+		cur.itc_b = b;
+		cur.itc_next = seen;
+		return it_cmp_recur(a->it_refp, b->it_refp, &cur);
+	}
 	if (a->it_refp == NULL)
 		return -1;
 	if (b->it_refp == NULL)
@@ -367,6 +384,12 @@ it_cmp(struct itype *a, struct itype *b)
 	return 0;
 }
 
+int
+it_cmp(struct itype *a, struct itype *b)
+{
+	return it_cmp_recur(a, b, NULL);
+}
+
 int
 it_name_cmp(struct itype *a, struct itype *b)
 {
```