# all-space archive name underflows buffer

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`make/arch.c:435`

## Summary

`read_archive()` trims trailing spaces from the fixed-width archive member name field without checking the lower bound of the stack buffer. If an archive header contains an `ar_name` field made entirely of spaces, the trimming loop decrements before `memberName` and then reads outside the stack object.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `make` hashes an attacker-supplied archive dependency.
- The archive has valid archive magic.
- The archive member header has a valid header terminator.
- The archive member header `ar_name` field is exactly 16 spaces.

## Proof

`read_archive()` copies the fixed 16-byte `ar_name` field into a stack buffer:

```c
(void)memcpy(memberName, arHeader.ar_name, AR_NAME_SIZE);
```

It then initializes `cp` to the final copied byte and strips spaces:

```c
for (cp = memberName + AR_NAME_SIZE - 1; *cp == ' ';)
	cp--;
cp[1] = '\0';
```

For an all-space 16-byte name:

- The loop reads each in-buffer byte.
- After the first byte is processed, `cp--` moves `cp` to `memberName - 1`.
- The next loop condition evaluates `*cp`.
- That evaluation reads before the stack buffer.

Reachability is confirmed through archive dependency hashing:

- `Dir_MTime()` reaches `Arch_MTime()` for `OP_ARCHV` nodes.
- `Arch_MTime()` calls `ArchMTimeMember(..., true)`.
- On archive cache miss, `ArchMTimeMember()` calls `read_archive()`.
- The invalid read occurs before member data seeking, so no valid member body is required.

A small ASan proof-of-concept using a crafted archive header reproduced the issue and reported a stack-buffer-underflow on the loop condition.

## Why This Is A Real Bug

The archive name field is fixed-width and not null-terminated. The parser must handle all valid byte patterns in that field without reading outside its destination buffer. An all-space field is enough to make the current loop step one byte before `buffer` and dereference it. This is attacker-controllable when a local source package author supplies an archive dependency consumed by `make`.

## Fix Requirement

Stop trimming when the cursor reaches the start of `memberName`; never evaluate `*cp` after `cp` has moved before the copied archive name buffer.

## Patch Rationale

The patch adds a lower-bound guard to the trimming loop:

```c
for (cp = memberName + AR_NAME_SIZE - 1;
    cp > memberName && *cp == ' ';)
	cp--;
```

This preserves the existing behavior for ordinary names with trailing spaces while preventing `cp` from underflowing below `memberName`. For an all-space name, the loop stops at the first byte, then `cp[1] = '\0'` safely terminates the copied name within the stack buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/make/arch.c b/make/arch.c
index 9fb18db..d268f81 100644
--- a/make/arch.c
+++ b/make/arch.c
@@ -430,7 +430,8 @@ read_archive(const char *archive, const char *earchive)
 			(void)memcpy(memberName, arHeader.ar_name,
 			    AR_NAME_SIZE);
 			/* Find real end of name (strip extraneous ' ')  */
-			for (cp = memberName + AR_NAME_SIZE - 1; *cp == ' ';)
+			for (cp = memberName + AR_NAME_SIZE - 1;
+			    cp > memberName && *cp == ' ';)
 				cp--;
 			cp[1] = '\0';

```