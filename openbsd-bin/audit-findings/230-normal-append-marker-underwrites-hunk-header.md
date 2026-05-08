# Normal Append Marker Underwrites Hunk Header

## Classification

Out-of-bounds write, high severity. Confidence: certain.

## Affected Locations

`usr.bin/patch/pch.c:817`

## Summary

The normal-diff parser handles a `\ No newline at end of file` marker after the old-line loop even when an append hunk has zero old lines. For append hunks, `p_ptrn_lines == 0`, so the old-line loop is skipped and `i == 1`. If the next attacker-controlled patch line begins with `\`, `remove_special_line()` consumes it and the code decrements `p_len[i - 1]`, i.e. `p_len[0]`, then writes through `p_line[0][p_len[0]]`. Because `p_len[0]` was never initialized for the synthetic hunk header, it remains zero from `calloc`, producing a one-byte heap write before the header allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Victim runs `patch` on an attacker-supplied normal diff.
- The diff contains a normal append hunk with zero old lines.
- The next line after the append command starts with `\`.

## Proof

Reproduced with an ASan harness using committed `usr.bin/patch/pch.c`.

Triggering patch:

```diff
1c1
< old
---
> changed
1a2
\ No newline at end of file
> new
```

Observed execution path:

- `p_len` is allocated by `calloc` at `usr.bin/patch/pch.c:126`, so `p_len[0]` starts as zero.
- The normal append command sets `p_ptrn_lines = 0`.
- The old-line loop at `usr.bin/patch/pch.c:1075` is skipped, leaving `i == 1`.
- `remove_special_line()` returns true when the next patch-file byte is `\`, via `usr.bin/patch/pch.c:422`.
- The code at `usr.bin/patch/pch.c:1094` decrements `p_len[0]` from `0` to `-1`.
- The code at `usr.bin/patch/pch.c:1095` writes to `p_line[0][-1]`.

ASan reports `heap-buffer-overflow` at `usr.bin/patch/pch.c:1095`, one byte before the 9-byte synthetic header allocation made at `usr.bin/patch/pch.c:1069`.

## Why This Is A Real Bug

The marker handling assumes at least one old line exists, but normal append hunks intentionally have zero old lines. In that case, `i - 1` refers to the synthetic `"***"` hunk header rather than an attacker-supplied old line. The header length slot is not set before this path, so decrementing it underflows the index used for the terminating NUL write. The result is attacker-triggered heap memory corruption and denial of service.

## Fix Requirement

Skip old-line newline-marker handling when the normal-diff hunk has no old lines.

## Patch Rationale

The patch gates the old-line `remove_special_line()` call on `p_ptrn_lines != 0`. This preserves existing behavior for change/delete hunks that actually parsed old lines, while preventing append hunks from applying old-line marker trimming to the synthetic header at `p_line[0]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/patch/pch.c b/usr.bin/patch/pch.c
index 7c65062..915d3ac 100644
--- a/usr.bin/patch/pch.c
+++ b/usr.bin/patch/pch.c
@@ -1090,7 +1090,7 @@ hunk_done:
 			p_char[i] = '-';
 		}
 
-		if (remove_special_line()) {
+		if (p_ptrn_lines != 0 && remove_special_line()) {
 			p_len[i - 1] -= 1;
 			(p_line[i - 1])[p_len[i - 1]] = 0;
 		}
```