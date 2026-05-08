# Quoted Bind Key Sequence Overflows Key Buffer

## Classification

High severity out-of-bounds write.

## Affected Locations

`usr.bin/mg/extend.c:832`

## Summary

`excline()` parses startup, eval-file, eval-buffer, and eval-expression lines. For quoted key arguments to `global-set-key`, `local-set-key`, and `define-key`, it decodes the quoted string directly into `key.k_chars` while incrementing `key.k_count`.

The vulnerable write:

```c
key.k_chars[key.k_count++] = c;
```

had no `MAXKEY` bound check. A quoted bind key sequence longer than `key.k_chars` capacity writes past the key buffer before `bindkey()` is called.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `mg` evaluates attacker-controlled startup, eval file, eval buffer, or eval expression input.
- The evaluated line contains a quoted bind key argument for `global-set-key`, `local-set-key`, or `define-key`.
- The decoded quoted key sequence exceeds `MAXKEY`.

## Proof

Reachability:

- `load()` evaluates startup or loaded file lines through `excline()` in `usr.bin/mg/extend.c`.
- `evalbuffer()` evaluates buffer lines through `excline()`.
- `evalexpr()` evaluates a user-provided line through `excline()`.

Propagation:

- `excline()` marks `global-set-key`, `local-set-key`, and `define-key` key arguments as `BINDARG`.
- For quoted `BINDARG` input, `excline()` sets `key.k_count = 0`.
- It then decodes each quoted character or escape and writes it into `key.k_chars`.

Failing operation:

```c
key.k_chars[key.k_count++] = c;
```

The write occurs without checking `key.k_count < MAXKEY`. Since `key.k_chars` capacity is `MAXKEY`, the 9th decoded character writes out of bounds when `MAXKEY` is 8.

Existing guarded path:

- `dobindkey()` bounds decoded key writes with `i < MAXKEY`.
- The quoted `BINDARG` parser in `excline()` bypasses that guarded path and calls `bindkey()` only after filling `key.k_chars`.

Impact:

- Attacker-controlled out-of-bounds write into editor memory.
- Practical memory corruption or denial of service from a malicious evaluated `mg` command file or buffer.

## Why This Is A Real Bug

The vulnerable parser writes decoded attacker-controlled bytes into a fixed-size global key buffer without enforcing the buffer limit. The write happens before later binding logic can validate or reject the key sequence.

The bug is independently evidenced by:

- A fixed-size destination: `key.k_chars`.
- A capacity constant: `MAXKEY`.
- An unbounded incrementing index: `key.k_count++`.
- A comparable safe implementation in `dobindkey()` that explicitly limits writes with `i < MAXKEY`.
- Reachable attacker-controlled input paths through startup/eval processing.

## Fix Requirement

Reject or truncate quoted `BINDARG` writes once `key.k_count` reaches `MAXKEY`.

Rejecting is preferable because it preserves exact binding semantics and prevents silently binding a truncated key sequence.

## Patch Rationale

The patch rejects overlong quoted bind key sequences before writing:

```c
if (key.k_count >= MAXKEY) {
	status = FALSE;
	goto cleanup;
}
key.k_chars[key.k_count++] = c;
```

This preserves existing behavior for valid key sequences and prevents the out-of-bounds write for overlong sequences. On overflow, parsing fails and uses the existing `cleanup` path to free allocated line structures.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/mg/extend.c b/usr.bin/mg/extend.c
index e4a539d..982f052 100644
--- a/usr.bin/mg/extend.c
+++ b/usr.bin/mg/extend.c
@@ -832,9 +832,13 @@ excline(char *line, int llen, int lnum)
 					}
 					argp++;
 				}
-				if (bind == BINDARG)
+				if (bind == BINDARG) {
+					if (key.k_count >= MAXKEY) {
+						status = FALSE;
+						goto cleanup;
+					}
 					key.k_chars[key.k_count++] = c;
-				else
+				} else
 					lp->l_text[lp->l_used++] = c;
 			}
 			if (*line)
```