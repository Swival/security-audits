# Negative Indent Writes Before Line Buffer

## Classification

Memory corruption, high severity.

## Affected Locations

`lpr/filters/lpf.c:162`

## Summary

`lpf` accepts the `-i` indentation option with `atoi(optarg)` and uses the result as the initial output column for each input line. A negative indent makes `col` negative, and printable input reaches `&buf[0][col]` without a lower-bound check. This computes a pointer before the start of `buf` and writes attacker-controlled print data out of bounds in the filter process.

## Provenance

Verified and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- A print submitter can influence the `lpf -i` option.
- The submitted print data contains printable characters.
- The target printer uses `lpf` as its input filter.
- Reachability exists through raw LPD job submission from an allowed client: an `I...` control-file record is propagated into the filter argument.

## Proof

`main` parses `-i` with no lower-bound validation:

```c
case 'i':
        indent = atoi(optarg);
        break;
```

Each input line starts from that value:

```c
col = indent;
```

For printable characters, the default case only rejects columns that are too large or disallowed control characters:

```c
if (col >= width || (!literal && ch < ' ')) {
        col++;
        break;
}
cp = &buf[0][col];
```

When `indent` is negative, `col` remains negative for the first printable character. `&buf[0][col]` therefore points before `buf`, and the following write corrupts memory:

```c
*cp = ch;
```

The issue was reproduced with an ASAN build using:

```sh
printf 'A\n' | lpf_asan -i-100000
```

The ASAN build crashes in the write path at `lpr/filters/lpf.c:167`.

The normal local `lpr` client clamps negative `-i` values to `8`, so `lpr -i -1` does not carry a negative indent through. However, raw LPD submission remains reachable: `recvjob` stores control-file contents without validating `I` records, `printit` copies `I...` into the filter argument, and `print` passes that `indent` argument to the input filter.

## Why This Is A Real Bug

The vulnerable pointer expression is directly indexed by attacker-influenced state. A negative `indent` produces a negative `col`, and the code has no `col < 0` guard before computing `&buf[0][col]`. The subsequent assignment writes outside the bounds of the global line buffer.

The impact is memory corruption in the daemon-owned filter process. The local client-side clamp does not eliminate the bug because an allowed LPD client can submit a raw control file containing a negative `I` record.

## Fix Requirement

Reject negative indentation values or clamp them to zero before any line-processing code uses `indent`.

## Patch Rationale

The patch clamps negative `-i` values immediately after parsing. This preserves existing behavior for valid non-negative indentation values while ensuring every new line starts with `col >= 0`. With `col` non-negative, the existing `col >= width` check is sufficient to prevent writes outside the `buf[MAXREP][MAXWIDTH]` column range.

## Residual Risk

None

## Patch

```diff
diff --git a/lpr/filters/lpf.c b/lpr/filters/lpf.c
index 8c5ec68..7e6f305 100644
--- a/lpr/filters/lpf.c
+++ b/lpr/filters/lpf.c
@@ -86,7 +86,8 @@ main(int argc, char **argv)
 			length = atoi(optarg);
 			break;
 		case 'i':
-			indent = atoi(optarg);
+			if ((indent = atoi(optarg)) < 0)
+				indent = 0;
 			break;
 		case 'r':	/* map nl->cr-nl */
 			onlcr = 1;
```