# Nested ERE Groups Exhaust Parser Stack

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`regex/regcomp.c:296`

## Summary

Extended regular expression parsing recurses once per nested parenthesized group without a nesting-depth limit. A service that compiles attacker-controlled patterns with `REG_EXTENDED` can be crashed by deeply nested ERE parentheses that exhaust the process stack.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The target service accepts attacker-supplied regular expression patterns.
- The target service compiles those patterns with `REG_EXTENDED`.
- The compiling process has finite stack space, as normal for user-space processes.

## Proof

`regcomp()` dispatches extended patterns to `p_ere()`. `p_ere()` parses concatenated expressions by repeatedly calling `p_ere_exp()`.

When `p_ere_exp()` sees `(`:

- It increments `p->g->nsub`.
- It emits `OLPAREN`.
- If the next character is not `)`, it calls `p_ere(p, ')')` recursively before consuming the matching `)`.

There was no limit on this recursive path. `NPAREN` only bounds stored bookkeeping for groups 1-9; it does not cap `g->nsub` or parenthesis nesting depth.

A harness compiled against `regex/regcomp.c` and `regex/regfree.c` reproduced the crash with generated patterns of the form:

```text
((((...(((a)))...))))
```

Observed results:

- With a 128 KiB stack, nesting depth `n=1000` crashed with `SIGSEGV`.
- Smaller values returned normally.
- With the default stack, `n=40000` succeeded and `n=80000` crashed.

This demonstrates practical stack exhaustion caused solely by regex input size.

## Why This Is A Real Bug

The parser stack depth is directly attacker-controlled for ERE group nesting. Each non-empty nested `(` creates another C recursion frame through `p_ere_exp()` -> `p_ere()` -> `p_ere_exp()`. Because no depth check or iterative fallback existed before the recursive call, sufficiently nested input can terminate the compiling process, causing denial of service.

## Fix Requirement

Reject excessive parenthesis nesting before making the recursive `p_ere(p, ')')` call.

## Patch Rationale

The patch adds parser-local nesting accounting:

- Adds `p->nest` to `struct parse`.
- Defines `NESTMAX` as `DUPMAX`, reusing an existing regex implementation bound.
- Initializes `p->nest` to zero in `regcomp()`.
- Checks `p->nest >= NESTMAX` before recursive ERE parsing.
- Sets `REG_ESPACE` instead of recursing when the nesting limit is reached.
- Increments `p->nest` before recursion and decrements it after returning.

This caps parser recursion from nested ERE groups while preserving existing behavior for valid patterns within the limit.

## Residual Risk

None

## Patch

```diff
diff --git a/regex/regcomp.c b/regex/regcomp.c
index ab71e9c..4f2899a 100644
--- a/regex/regcomp.c
+++ b/regex/regcomp.c
@@ -60,8 +60,10 @@ struct parse {
 	sopno ssize;		/* malloced strip size (allocated) */
 	sopno slen;		/* malloced strip length (used) */
 	int ncsalloc;		/* number of csets allocated */
+	int nest;		/* parenthesis nesting depth */
 	struct re_guts *g;
 #	define	NPAREN	10	/* we need to remember () 1-9 for back refs */
+#	define	NESTMAX	DUPMAX	/* maximum parenthesis nesting depth */
 	sopno pbegin[NPAREN];	/* -> ( ([0] unused) */
 	sopno pend[NPAREN];	/* -> ) ([0] unused) */
 };
@@ -180,6 +182,7 @@ regcomp(regex_t *preg, const char *pattern, int cflags)
 	p->end = p->next + len;
 	p->error = 0;
 	p->ncsalloc = 0;
+	p->nest = 0;
 	for (i = 0; i < NPAREN; i++) {
 		p->pbegin[i] = 0;
 		p->pend[i] = 0;
@@ -297,8 +300,15 @@ p_ere_exp(struct parse *p)
 		if (subno < NPAREN)
 			p->pbegin[subno] = HERE();
 		EMIT(OLPAREN, subno);
-		if (!SEE(')'))
-			p_ere(p, ')');
+		if (!SEE(')')) {
+			if (p->nest >= NESTMAX)
+				SETERROR(REG_ESPACE);
+			else {
+				p->nest++;
+				p_ere(p, ')');
+				p->nest--;
+			}
+		}
 		if (subno < NPAREN) {
 			p->pend[subno] = HERE();
 			assert(p->pend[subno] != 0);
```