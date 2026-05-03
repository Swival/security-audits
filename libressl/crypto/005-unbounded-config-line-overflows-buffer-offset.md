# Unbounded Config Line Overflows Buffer Offset

## Classification

Denial of service, medium severity.

## Affected Locations

`conf/conf_def.c:169`

`conf/conf_def.c:186`

## Summary

`def_load_bio()` accumulates continued or newline-free configuration input into `buff->data` while tracking the logical-line offset in `bufnum`. The original implementation used signed `int` arithmetic for `bufnum`, `i`, and `ii`, allowing an attacker-controlled oversized logical line to trigger signed integer overflow during config parsing.

The reproduced overflow occurs before `bufnum += i`: once `bufnum` approaches `INT_MAX`, the next loop evaluates `bufnum + CONFBUFSIZE` for `BUF_MEM_grow()`, overflowing signed `int`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The application parses attacker-controlled configuration data with `def_load_bio()`.
- The attacker can supply a newline-free logical line or a continued logical line using trailing backslashes.
- The process can parse or allocate multi-GB attacker-controlled input before the overflow point.

## Proof

`def_load_bio()` repeatedly reads up to `CONFBUFSIZE - 1` bytes with `BIO_gets()` into `buff->data + bufnum`.

For physical lines without a newline, or physical lines continued with a trailing backslash, `again` remains true and parsing continues without resetting `bufnum`.

The original code then repeatedly grows the buffer with:

```c
BUF_MEM_grow(buff, bufnum + CONFBUFSIZE)
```

and later advances the offset with:

```c
bufnum += i;
```

Because `bufnum`, `i`, and `ii` were `int`, the accumulated logical-line length was bounded only by available input and memory, not by type-safe arithmetic.

Reproduction confirmed a reachable signed overflow in `bufnum + CONFBUFSIZE` at `conf/conf_def.c:169`. An attacker-controlled continued config line can steer chunk sizes via trailing-backslash physical lines, reach a buffer allocation near `INT_MAX`, then append another no-newline chunk so the next loop evaluates `bufnum + 512` as signed `int` overflow.

## Why This Is A Real Bug

Signed integer overflow in C is undefined behavior. In this parser, the overflowing operands are derived from attacker-controlled config input length.

The existing buffer growth limits do not fully prevent the condition. Reproduction showed `BUF_MEM_grow_clean()` can allow a grow request near `0x5ffffffc`, after which `buff->max` expands near `INT_MAX`. A later `bufnum + CONFBUFSIZE` expression can still overflow before a parsing error is raised.

Practical impact is denial of service: trapping or sanitizer-instrumented builds can abort, and UB-sensitive executions can crash or hang during configuration parsing.

## Fix Requirement

- Do not track logical-line offsets with signed `int`.
- Avoid signed overflow in buffer growth calculations.
- Reject attacker-controlled logical config lines above a sane maximum before continuing accumulation.

## Patch Rationale

The patch changes `bufnum`, `i`, and `ii` to `size_t`, matching buffer sizes and preventing signed arithmetic overflow in the line accumulation path.

It also adds an explicit logical-line length check before `bufnum += i`:

```c
if (i > MAX_CONF_VALUE_LENGTH - bufnum) {
	CONFerror(CONF_R_VARIABLE_EXPANSION_TOO_LONG);
	goto err;
}
```

This caps accumulated logical config lines at `MAX_CONF_VALUE_LENGTH`, preventing unbounded growth and ensuring oversized attacker-controlled lines fail safely before advancing the offset.

## Residual Risk

None

## Patch

```diff
diff --git a/conf/conf_def.c b/conf/conf_def.c
index fe93916..3fef9ed 100644
--- a/conf/conf_def.c
+++ b/conf/conf_def.c
@@ -130,7 +130,7 @@ def_load_bio(CONF *conf, BIO *in, long *line)
 {
 /* The macro BUFSIZE conflicts with a system macro in VxWorks */
 #define CONFBUFSIZE	512
-	int bufnum = 0, i, ii;
+	size_t bufnum = 0, i, ii;
 	BUF_MEM *buff = NULL;
 	char *s, *p, *end;
 	int again;
@@ -196,6 +196,10 @@ def_load_bio(CONF *conf, BIO *in, long *line)
 		/* we now have a line with trailing \r\n removed */
 
 		/* i is the number of bytes */
+		if (i > MAX_CONF_VALUE_LENGTH - bufnum) {
+			CONFerror(CONF_R_VARIABLE_EXPANSION_TOO_LONG);
+			goto err;
+		}
 		bufnum += i;
 
 		v = NULL;
```