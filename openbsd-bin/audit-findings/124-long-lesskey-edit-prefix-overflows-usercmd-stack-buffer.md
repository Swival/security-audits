# long lesskey edit prefix overflows usercmd stack buffer

## Classification

Out-of-bounds write. Medium severity. Confidence: certain.

## Affected Locations

`usr.bin/less/decode.c:739`

## Summary

`editchar()` collects typed edit-command bytes into `char usercmd[MAX_CMDLEN+1]` while `ecmd_decode()` reports that the current bytes are a prefix of a longer edit command. A non-secure `less` process can load attacker-controlled lesskey edit tables. If an attacker supplies an edit command longer than `MAX_CMDLEN`, repeated `A_PREFIX` results let `nch` exceed the stack buffer bounds and overwrite adjacent stack memory.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- `less` runs with `secure == false`.
- `less` loads an attacker-controlled `LESSKEY` file.
- The lesskey file contains an `EDIT_SECTION` entry with a command prefix longer than `MAX_CMDLEN`.
- The attacker can cause the matching command bytes to be typed into a line-editing context.

## Proof

`lesskey()` loads user-selected lesskey files when `secure` is false, and `new_lesskey()` installs `EDIT_SECTION` bytes through `add_ecmd_table()`.

In `editchar()`, the stack buffer is declared as:

```c
char usercmd[MAX_CMDLEN+1];
```

The collection loop writes the current byte and a terminator before checking any length limit:

```c
usercmd[nch] = (char)c;
usercmd[nch+1] = '\0';
nch++;
action = ecmd_decode(usercmd, &s);
```

`cmd_search()` returns `A_PREFIX` when the typed bytes are a proper prefix of a longer table entry. That causes `editchar()` to continue reading bytes:

```c
} while (action == A_PREFIX);
```

A crafted edit binding of 18 `A` bytes followed by NUL and `EC_RIGHT`, then entering search mode and typing 18 `A`s, reaches the overflow. With `MAX_CMDLEN == 16`, the 17th typed byte writes the terminator at `usercmd[17]`, and the 18th typed byte writes attacker-controlled input past the stack buffer.

A small ASan harness copied from the committed `editchar()` / `cmd_search()` path reports a stack-buffer-overflow on the `usercmd[nch+1] = '\0'` write with an 18-byte edit command prefix.

## Why This Is A Real Bug

The edit-command table is attacker-controlled under the stated preconditions, and the decoder explicitly treats typed bytes as an incomplete prefix of attacker-supplied longer commands. Because `editchar()` has no `nch` bound before writing `usercmd[nch]` and `usercmd[nch+1]`, valid control flow writes beyond a fixed-size stack buffer. The overflow contents are derived from terminal input controlled by the attacker.

## Fix Requirement

Stop collecting additional edit-command bytes once `nch` reaches `MAX_CMDLEN`, or reject the command before any write can exceed `usercmd[MAX_CMDLEN]`.

## Patch Rationale

The patch limits the prefix-collection loop to `nch < MAX_CMDLEN`:

```diff
-	} while (action == A_PREFIX);
+	} while (action == A_PREFIX && nch < MAX_CMDLEN);
+	if (action == A_PREFIX)
+		action = A_INVALID;
```

This preserves valid decoding for commands up to `MAX_CMDLEN` while preventing the next iteration from writing `usercmd[MAX_CMDLEN+1]` or beyond. If the only reason decoding would continue is an overlong prefix, the command is treated as invalid instead of continuing to collect bytes unsafely.

## Residual Risk

None

## Patch

`124-long-lesskey-edit-prefix-overflows-usercmd-stack-buffer.patch`

```diff
diff --git a/usr.bin/less/decode.c b/usr.bin/less/decode.c
index 4846e0c..95bf75c 100644
--- a/usr.bin/less/decode.c
+++ b/usr.bin/less/decode.c
@@ -737,7 +737,9 @@ editchar(int c, int flags)
 		usercmd[nch+1] = '\0';
 		nch++;
 		action = ecmd_decode(usercmd, &s);
-	} while (action == A_PREFIX);
+	} while (action == A_PREFIX && nch < MAX_CMDLEN);
+	if (action == A_PREFIX)
+		action = A_INVALID;
 
 	if (flags & EC_NORIGHTLEFT) {
 		switch (action) {
```