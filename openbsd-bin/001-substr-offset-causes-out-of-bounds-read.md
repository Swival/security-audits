# substr offset causes out-of-bounds read

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`m4/eval.c:874`

## Summary

`substr()` accepts an attacker-controlled target string and offset. `dosubstr()` computed `fc = ap + offset` before validating that the offset was inside the target string, then immediately called `strlen(fc)`. An out-of-range offset can therefore make `strlen()` read from an invalid pointer, causing memory-safety undefined behavior and practical process termination.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The processor evaluates attacker-controlled m4 input containing `substr()` arguments.

## Proof

`substr` is exposed as a builtin in `m4/main.c:96`. `expand_builtin()` dispatches `SUBSTRTYPE` to `dosubstr()` when `argc > 3`, so an input call with a target string and offset reaches the vulnerable code.

In `dosubstr()`, `ap` is assigned from attacker-controlled `argv[2]`. The first-character pointer was computed from attacker-controlled `argv[3]`:

```c
ap = argv[2];
fc = ap + expr(argv[3]); /* or atoi(argv[3]) */
nc = strlen(fc);
```

The bounds check occurred only after `strlen(fc)`:

```c
if (fc >= ap && fc < ap + strlen(ap))
```

A trigger such as:

```m4
substr(a,2147483647)
```

can form a pointer far outside the parsed argument storage and dereference it through `strlen()`, causing attacker-triggered invalid memory access and denial of service.

## Why This Is A Real Bug

The offset argument is attacker-controlled and no earlier control rejects an out-of-range value. `argc > 3` only proves the offset argument exists; it does not prove that the offset is non-negative or within `strlen(ap)`. Because C pointer arithmetic outside the referenced object and the subsequent `strlen()` dereference are undefined behavior, the reachable call path is a real memory-safety bug.

## Fix Requirement

Validate the parsed offset against the target string length before forming or reading from `fc`.

## Patch Rationale

The patch stores the parsed offset in an integer, computes `len = strlen(ap)`, and returns before pointer arithmetic if the offset is negative or greater than or equal to the target length. Only after this validation does it compute `fc = ap + offset` and call `strlen(fc)`.

The later range check is retained but changed to reuse the already computed `len`, avoiding a duplicate `strlen(ap)`.

## Residual Risk

None

## Patch

```diff
diff --git a/m4/eval.c b/m4/eval.c
index 9ee73fc..c88ecfb 100644
--- a/m4/eval.c
+++ b/m4/eval.c
@@ -871,13 +871,19 @@ dosubstr(const char *argv[], int argc)
 {
 	const char *ap, *fc, *k;
 	int nc;
+	int offset;
+	size_t len;
 
 	ap = argv[2];		       /* target string */
 #ifdef EXPR
-	fc = ap + expr(argv[3]);       /* first char */
+	offset = expr(argv[3]);	       /* first char */
 #else
-	fc = ap + atoi(argv[3]);       /* first char */
+	offset = atoi(argv[3]);	       /* first char */
 #endif
+	len = strlen(ap);
+	if (offset < 0 || (size_t)offset >= len)
+		return;
+	fc = ap + offset;
 	nc = strlen(fc);
 	if (argc >= 5)
 #ifdef EXPR
@@ -885,7 +891,7 @@ dosubstr(const char *argv[], int argc)
 #else
 		nc = min(nc, atoi(argv[4]));
 #endif
-	if (fc >= ap && fc < ap + strlen(ap))
+	if (fc >= ap && fc < ap + len)
 		for (k = fc + nc - 1; k >= fc; k--)
 			pushback(*k);
 }
```