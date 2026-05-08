# NUL output stalls parser loop

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/watch/watch.c:563`

## Summary

`watch` can enter an infinite parser loop when the monitored subprocess emits a NUL byte. `mbtowc()` returns `0` for NUL input, but `child_input()` treats this as a successful conversion and advances the input offset by `len`. Because `len == 0`, the offset does not advance, so the same byte is processed forever and the terminal UI freezes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The user runs `watch` on a subprocess whose stdout or stderr is attacker-controlled.

## Proof

`start_child()` redirects the monitored command's stdout and stderr into a pipe consumed by `child_input()`.

In `child_input()`, subprocess output is read into `child->buf`, then parsed with:

```c
for (size_t i = 0; i < child->pos;/* i += len */) {
	wchar_t wc;
	int len = mbtowc(&wc, &child->buf[i], MB_CUR_MAX);
	if (len == -1) {
		wc = '?';
		i += 1;
	} else {
		i += len;
	}
```

For an input NUL byte, `mbtowc(&wc, &child->buf[i], MB_CUR_MAX)` returns `0`. The non-error branch executes `i += len`, leaving `i` unchanged.

The parsed wide character is `L'\0'`. It is not newline or tab, so execution reaches the column handling path. `c` increments until `MAXCOLUMN`; after that, this branch repeats forever without changing `i`:

```c
if (c == MAXCOLUMN)
	continue;
```

Result: `child_input()` never returns to libevent, freezing the `watch` UI and causing a user-visible denial of service.

## Why This Is A Real Bug

This is not a theoretical parser edge case. C library `mbtowc()` explicitly returns `0` when the converted character is the null wide character. The loop invariant requires every successful iteration to consume at least one byte, but the NUL case violates that invariant. Because the loop body has a `continue` path after `c == MAXCOLUMN`, the function can spin indefinitely on the same input byte and block the event loop.

## Fix Requirement

Treat `mbtowc()` returning `0` as one consumed input byte before continuing parser execution.

## Patch Rationale

The patch preserves existing behavior for valid multibyte characters and invalid byte sequences while restoring forward progress for embedded NUL bytes. A NUL byte is one byte in the input stream, so normalizing `len == 0` to `1` consumes the offending byte and prevents the parser from reprocessing it indefinitely.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/watch/watch.c b/usr.bin/watch/watch.c
index 7d1b788..910b65e 100644
--- a/usr.bin/watch/watch.c
+++ b/usr.bin/watch/watch.c
@@ -565,6 +565,8 @@ child_input(int sig, short event, void *arg)
 			wc = '?';
 			i += 1;
 		} else {
+			if (len == 0)
+				len = 1;
 			i += len;
 		}
 		if (wc == '\n') {
```