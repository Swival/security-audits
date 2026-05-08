# Empty Bind Key Sequence Underflows Key Count

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.bin/mg/extend.c:400`

## Summary

`mg` can hang, exhaust memory, or crash when evaluating a bind command whose quoted key sequence is empty, such as:

```text
global-set-key "" self-insert-command
```

The empty quoted key sequence produces `kcount == 0`. `bindkey()` then executes `while (--kcount)`, underflowing the count to `-1` and entering a loop that reads past the key buffer.

## Provenance

Verified from the provided source and reproduced analysis.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `mg` evaluates attacker-controlled line commands.
- The attacker can place or supply a startup, batch, eval, or buffer command line evaluated by `excline()`.
- The evaluated command contains an empty quoted key sequence for a bind operation.

## Proof

A triggering command is:

```text
global-set-key "" self-insert-command
```

Equivalent local binding also triggers:

```text
local-set-key "" self-insert-command
```

Execution path:

- `excline()` parses the quoted first bind argument as `BINDARG`.
- For `""`, no characters are copied and `key.k_count` remains `0`.
- Parsing transitions to `BINDDO`.
- `BINDDO` calls:

```c
bindkey(&curmap, lp->l_text, key.k_chars, key.k_count);
```

with `kcount == 0`.

In `bindkey()`:

```c
while (--kcount) {
```

When `kcount` is `0`, the pre-decrement changes it to `-1`. The loop condition remains true, so the loop proceeds and repeatedly reads from `*keys++` beyond the valid `key.k_chars` data while calling `doscan()` and `remap()`.

Impact is denial of service through a hang, repeated keymap allocation/memory exhaustion, or a fault from out-of-bounds reads.

## Why This Is A Real Bug

The parser explicitly permits an empty quoted string as the bind key argument and represents it as a zero-length key sequence. `bindkey()` does not validate that the sequence contains at least one key before using pre-decrement loop logic that assumes a positive count.

This is not merely a rejected invalid command: the invalid zero-length sequence reaches binding logic and drives out-of-bounds scanning behavior.

## Fix Requirement

Reject non-positive key counts before entering the `bindkey()` loop.

The binding operation must fail safely when `kcount <= 0`.

## Patch Rationale

The patch adds an early validation guard in `bindkey()`:

```c
if (kcount <= 0)
	return (FALSE);
```

This prevents the `while (--kcount)` underflow path and ensures no dereference of `keys` occurs unless at least one key is present.

The check is placed after function/map name validation and before any key sequence traversal, preserving existing behavior for valid bindings while safely rejecting empty sequences.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/mg/extend.c b/usr.bin/mg/extend.c
index e4a539d..f6ef5cc 100644
--- a/usr.bin/mg/extend.c
+++ b/usr.bin/mg/extend.c
@@ -397,6 +397,8 @@ bindkey(KEYMAP **mapp, const char *fname, KCHAR *keys, int kcount)
 		ewprintf("[No match: %s]", fname);
 		return (FALSE);
 	}
+	if (kcount <= 0)
+		return (FALSE);
 	while (--kcount) {
 		if (doscan(curmap, c = *keys++, &curmap) != NULL) {
 			if (remap(curmap, c, NULL, NULL) != TRUE)
```