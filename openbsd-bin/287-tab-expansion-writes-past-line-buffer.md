# Tab Expansion Writes Past Line Buffer

## Classification

Out-of-bounds write, medium severity.

## Affected Locations

`usr.bin/ul/ul.c:210`

## Summary

`ul` stores formatted line cells in the global array `obuf[MAXBUF]`. During tab expansion, `mfilter()` writes synthetic space cells until it reaches the next tab stop, but the expansion loop does not check that `col` remains below `MAXBUF` before writing `obuf[col]`.

An attacker-controlled input line with 510 spaces followed by a tab can advance `col` to 511, then cause the tab expansion loop to write `obuf[512]`, one element past the end of the 512-element global buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs `ul` on attacker-controlled input.
- The input contains a crafted line that reaches the end of the internal display-cell buffer immediately before a tab expansion.

## Proof

Reproducer:

- Input: 510 ASCII spaces followed by a tab.
- `mfilter()` starts with `col = 1`.
- After processing 510 spaces, `col == 511`.
- `obuf[510].c_pos == 510`.
- For the tab, `wt = (obuf[col - 1].c_pos + 8) & ~7`, so `wt == 512`.
- The tab expansion loop writes `obuf[511]`, increments `col` to 512, then writes `obuf[512]`.
- `obuf` is declared as `struct CHAR obuf[MAXBUF]` with `MAXBUF == 512`, so valid indices are `0` through `511`.

ASan confirmed a `global-buffer-overflow` write at `usr.bin/ul/ul.c:212`, 8 bytes past global `obuf`.

## Why This Is A Real Bug

The outer read loop only enforces `col < MAXBUF` before entering each switch iteration. The tab expansion case performs additional writes and increments `col` inside an inner loop without rechecking the buffer bound.

When `col` reaches `MAXBUF` inside that inner loop, the next iteration still evaluates `w < wt` and writes `obuf[col]`, producing an out-of-bounds global write. This can crash `ul` or corrupt adjacent global state.

## Fix Requirement

Bound tab expansion by `MAXBUF` before each write to `obuf[col]`.

## Patch Rationale

The patch changes the tab expansion loop condition from:

```c
while (w < wt) {
```

to:

```c
while (w < wt && col < MAXBUF) {
```

This preserves existing tab expansion behavior while space remains in `obuf`, and stops expansion before `col` can equal `MAXBUF`. Because the writes in the loop target `obuf[col]`, checking `col < MAXBUF` in the loop condition prevents `obuf[MAXBUF]` and later out-of-bounds writes.

## Residual Risk

None.

## Patch

```diff
diff --git a/usr.bin/ul/ul.c b/usr.bin/ul/ul.c
index 7803df1..f4c88cd 100644
--- a/usr.bin/ul/ul.c
+++ b/usr.bin/ul/ul.c
@@ -208,7 +208,7 @@ mfilter(FILE *f)
 			/* Advance beyond the end. */
 			if (w == 0) {
 				w = obuf[col - 1].c_pos;
-				while (w < wt) {
+				while (w < wt && col < MAXBUF) {
 					obuf[col].c_width = 1;
 					obuf[col++].c_pos = ++w;
 				}
```