# AIX acs_chars stack off-by-one

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/tic/dump_entry.c:1226`

## Summary

The AIX terminfo dump path builds an 11-character `boxchars` string from attacker-controlled `acs_chars`, but allocates only 11 bytes and then writes a NUL terminator. If all eleven expected AIX ACS keys are present, the terminator write lands one byte past the stack buffer.

## Provenance

Verified from supplied source, reproducer summary, and patch. Initially reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `dump_init` selects AIX output via version string `"AIX"`.
- `acs_chars` is a valid string.
- The local user supplies a terminfo entry whose `acsc` contains all eleven keys from `lqkxjmwuvtn`.

## Proof

A reproduced trigger is:

```sh
tic -I -R AIX <file>
```

The user-controlled `-R AIX` path selects `V_AIX` in `dump_init`, and `dump_entry` reaches `FMT_ENTRY()`.

In the AIX branch of `fmt_entry`:

- `acstrans` is `"lqkxjmwuvtn"`, containing eleven keys.
- `boxchars` was declared as `char boxchars[11]`.
- The loop appends one mapped byte for each key found in `acs_chars`.
- With `acsc=lAqBkCxDjEmFwGuHvItJnK`, all eleven keys are found, so `tp == boxchars + 11`.
- The subsequent `tp[0] = '\0'` writes one byte past `boxchars`.

The reproducer summary states an ASan harness of the exact block reports `stack-buffer-overflow` on the terminator write.

## Why This Is A Real Bug

This is not a theoretical bounds mismatch. The loop can write exactly eleven data bytes into an eleven-byte stack array and then unconditionally writes a twelfth byte for the terminator. The input string is attacker-controlled through a local terminfo entry processed by `tic -I -R AIX`, so the conversion process can be made to corrupt stack memory.

## Fix Requirement

The destination buffer must include room for every translated character plus the terminating NUL, or the append loop must enforce a capacity check before writing.

## Patch Rationale

The patch changes `acstrans` from a pointer to a fixed array:

```c
const char acstrans[] = "lqkxjmwuvtn";
```

and sizes `boxchars` from that array:

```c
char *tp, *sp, boxchars[sizeof(acstrans)];
```

Because `sizeof(acstrans)` includes the string terminator, `boxchars` now has twelve bytes: eleven translated characters plus one NUL. This directly matches the maximum loop output and preserves existing behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/tic/dump_entry.c b/usr.bin/tic/dump_entry.c
index 474fd3f..02d3c57 100644
--- a/usr.bin/tic/dump_entry.c
+++ b/usr.bin/tic/dump_entry.c
@@ -1210,9 +1210,9 @@ fmt_entry(TERMTYPE2 *tterm,
     } else if (tversion == V_AIX) {
 	if (VALID_STRING(acs_chars)) {
 	    bool box_ok = TRUE;
-	    const char *acstrans = "lqkxjmwuvtn";
+	    const char acstrans[] = "lqkxjmwuvtn";
 	    const char *cp;
-	    char *tp, *sp, boxchars[11];
+	    char *tp, *sp, boxchars[sizeof(acstrans)];
 
 	    tp = boxchars;
 	    for (cp = acstrans; *cp; cp++) {
```