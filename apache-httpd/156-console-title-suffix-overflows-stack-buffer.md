# Console Title Suffix Overflows Stack Buffer

## Classification

Memory safety: stack buffer overflow.

Severity: medium.

Confidence: certain.

## Affected Locations

- `support/win32/wintty.c:339`

## Summary

`wintty` copies the current console title into a fixed 1024-byte stack buffer and then appends `" - [Finished]"` with `strcat()`. A command-line-controlled `-t` title can make the buffer full before the append, causing the suffix append to write past the end of the stack buffer.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- The program is run with a console title controlled through `-t`.
- The console title is 1011 bytes before the finished suffix is appended.
- stdin reaches EOF, causing the post-loop title update path to execute.

## Proof

The `-t` option assigns `contitle` directly from the next command-line argument without a length limit. After `AllocConsole()`, the program calls `SetConsoleTitle(contitle)`, installing that user-controlled title.

When stdin reaches EOF, the program executes:

```c
GetConsoleTitle(str, sizeof(str));
strcat(str, " - [Finished]");
```

`str` is a 1024-byte stack buffer. With a 1011-byte title, `GetConsoleTitle(str, sizeof(str))` stores 1011 title bytes followed by a NUL at index 1011. The suffix `" - [Finished]"` contains 13 non-NUL bytes. `strcat()` then writes those 13 bytes plus the terminating NUL through index 1024, overflowing the 1024-byte buffer by one byte.

Practical trigger:

```text
wintty -t <1011-byte-title>
```

Then cause stdin EOF so the finished-title update path runs.

## Why This Is A Real Bug

The overflow is directly reachable from command-line input. The title value is user-controlled, installed into the console title, read back into a fixed-size stack buffer, and extended with an unbounded append. The stack buffer has insufficient remaining capacity for the suffix plus NUL when the title length is 1011 bytes.

## Fix Requirement

Replace the unbounded append with a bounded append that respects the remaining capacity of `str` and always leaves room for the terminating NUL.

## Patch Rationale

The patch changes:

```c
strcat(str, " - [Finished]");
```

to:

```c
strncat(str, " - [Finished]", sizeof(str) - strlen(str) - 1);
```

This limits the suffix append to the remaining writable capacity in `str`, excluding the existing content and reserving one byte for the terminating NUL. If the title already fills the buffer, no out-of-bounds write occurs.

## Residual Risk

None

## Patch

```diff
diff --git a/support/win32/wintty.c b/support/win32/wintty.c
index 684ce5b..f283a12 100644
--- a/support/win32/wintty.c
+++ b/support/win32/wintty.c
@@ -336,7 +336,7 @@ int main(int argc, char** argv)
         printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
     }
     else {
-        strcat(str, " - [Finished]");
+        strncat(str, " - [Finished]", sizeof(str) - strlen(str) - 1);
         if (!SetConsoleTitle(str)) {
             printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
         }
```