# unknown settc name writes past t_val

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`lib/libedit/terminal.c:1016`

Primary vulnerable logic is in `terminal_settc()` near `lib/libedit/terminal.c:1343`.

## Summary

`terminal_settc()` handles unknown numeric terminal capability names incorrectly. After failing to find a name in `tval[]`, the search stops on the sentinel entry, but the code continues instead of returning an error. A numeric value then causes a write to `el->el_terminal.t_val[8]`, one `int` past the `calloc(T_val, sizeof(int))` allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An application exposes `terminal_settc()` inputs to attacker-controlled arguments, directly or through public libedit APIs such as `el_parse()` or `el_set(..., EL_SETTC, ...)`.

## Proof

`terminal_init()` allocates:

```c
el->el_terminal.t_val = calloc(T_val, sizeof(int));
```

`T_val` is `8`, so valid indexes are `0..7`.

`terminal_settc()` searches `tval[]`:

```c
for (tv = tval; tv->name != NULL; tv++)
	if (strcmp(tv->name, what) == 0)
		break;
```

For an unknown name such as `zz`, the loop stops at the sentinel entry where `tv->name == NULL`, i.e. `tv == &tval[T_val]`.

The vulnerable code checks the wrong condition:

```c
if (tv->name != NULL)
	return -1;
```

Because `tv->name == NULL` for an unknown name, execution continues. With a numeric value such as `1`, `strtol()` succeeds and the code writes:

```c
el->el_terminal.t_val[tv - tval] = (int) i;
```

For the sentinel entry, `tv - tval == 8`, causing a one-`int` heap write past the allocation.

Concrete trigger after `el_init()`:

```text
settc zz 1
```

Equivalent direct API trigger:

```c
el_set(el, EL_SETTC, "zz", "1", NULL);
```

## Why This Is A Real Bug

The sentinel entry is not a valid writable terminal value. `t_val` is allocated for exactly `T_val` elements, but the sentinel position produces index `T_val`. The inverted NULL check makes unknown names reach the write path, producing deterministic heap memory corruption from attacker-controlled input when the API is exposed.

## Fix Requirement

Return `-1` when the numeric capability lookup reaches the sentinel, before using `tv - tval`.

## Patch Rationale

The patch changes the guard from accepting the sentinel to rejecting it:

```diff
-	if (tv->name != NULL)
+	if (tv->name == NULL)
 		return -1;
```

This matches the existing string-capability handling pattern and ensures only found `tval[]` entries are used for indexing `el->el_terminal.t_val`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libedit/terminal.c b/lib/libedit/terminal.c
index 7a9db20..c6fdcc5 100644
--- a/lib/libedit/terminal.c
+++ b/lib/libedit/terminal.c
@@ -1343,7 +1343,7 @@ terminal_settc(EditLine *el, int argc __attribute__((__unused__)),
 		if (strcmp(tv->name, what) == 0)
 			break;
 
-	if (tv->name != NULL)
+	if (tv->name == NULL)
 		return -1;
 
 	if (tv == &tval[T_pt] || tv == &tval[T_km] ||
```