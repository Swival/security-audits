# REPORT Capture Overflows Report Buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/pppd/chat/chat.c:878`

Additional reproduced write sites:

`usr.sbin/pppd/chat/chat.c:169`

`usr.sbin/pppd/chat/chat.c:1322`

`usr.sbin/pppd/chat/chat.c:1326`

`usr.sbin/pppd/chat/chat.c:1333`

`usr.sbin/pppd/chat/chat.c:1334`

`usr.sbin/pppd/chat/chat.c:1335`

## Summary

`chat` stores captured `REPORT` text in a fixed global `char report_buffer[50]`. After a configured `REPORT` marker is matched in peer-controlled modem input, subsequent printable bytes are appended to `report_buffer` without checking the buffer size. A long printable field after the marker writes past the end of `report_buffer`, corrupting adjacent global state and enabling denial of service or memory corruption.

## Provenance

Found by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and patch evidence.

## Preconditions

- The chat script configures a `REPORT` string.
- The peer controls modem-side input read by `get_char()`.
- The peer sends the configured marker followed by a long printable non-control field.

## Proof

`report_buffer` is declared as a fixed 50-byte global buffer at `usr.sbin/pppd/chat/chat.c:169`.

When `get_string()` receives input, it appends bytes into `temp` and checks whether the current suffix matches a configured `REPORT` string. On match, it initializes `report_buffer` with a timestamp and marker using `strftime()` and `strlcat()`, then sets `report_gathering = 1` at `usr.sbin/pppd/chat/chat.c:1322` and `usr.sbin/pppd/chat/chat.c:1326`.

After that point, every subsequent non-control byte enters the report gathering branch:

```c
int rep_len = strlen (report_buffer);
report_buffer[rep_len]     = c;
report_buffer[rep_len + 1] = '\0';
```

These writes occur at `usr.sbin/pppd/chat/chat.c:1333`, `usr.sbin/pppd/chat/chat.c:1334`, and `usr.sbin/pppd/chat/chat.c:1335`.

There is no bounds check before either write. Once `strlen(report_buffer)` reaches 49, the NUL terminator write targets index 50, which is one byte beyond `char report_buffer[50]`. On the next printable byte, peer-controlled data is written out of bounds.

A practical trigger is:

- Chat script includes `REPORT <marker>` followed by an expect operation.
- Remote/modem-side peer sends `<marker>` plus a long printable field without a control byte.
- `get_string()` captures the field and overflows `report_buffer`.

The termination path had the same boundary error pattern: `terminate()` used `while (rep_len + 1 <= sizeof(report_buffer))`, allowing a final NUL write at index 50.

## Why This Is A Real Bug

The input bytes appended to `report_buffer` are controlled by the remote PPP peer or modem-side input source. The buffer is a fixed 50-byte global object, and the append path writes both the byte and trailing NUL without verifying space for both. The reproducer shows that a field length reaching 49 causes an out-of-bounds NUL write, and continued printable input causes peer-controlled out-of-bounds writes. This is memory corruption, not just log truncation or malformed output.

## Fix Requirement

Every append to `report_buffer` must preserve space for the trailing NUL. The code must either:

- stop appending once `rep_len + 1 >= sizeof(report_buffer)`, or
- use a bounded append primitive that guarantees NUL termination without writing past the buffer.

The termination-time drain loop must use the same strict bound.

## Patch Rationale

The patch changes the termination loop bound from:

```c
while (rep_len + 1 <= sizeof(report_buffer))
```

to:

```c
while (rep_len + 1 < sizeof(report_buffer))
```

This prevents the loop from appending when only the out-of-bounds NUL slot would remain.

The patch also guards the live `get_string()` append:

```c
if (rep_len + 1 < sizeof(report_buffer)) {
    report_buffer[rep_len]     = c;
    report_buffer[rep_len + 1] = '\0';
}
```

This allows an append only when there is room for both the new byte and the terminating NUL. Excess printable bytes are ignored while gathering continues, preserving the existing behavior of ending capture on a control byte and printing the truncated report safely.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pppd/chat/chat.c b/usr.sbin/pppd/chat/chat.c
index 596a83c..818fe87 100644
--- a/usr.sbin/pppd/chat/chat.c
+++ b/usr.sbin/pppd/chat/chat.c
@@ -543,7 +543,7 @@ void terminate(int status)
 	    int c, rep_len;
 
 	    rep_len = strlen(report_buffer);
-	    while (rep_len + 1 <= sizeof(report_buffer)) {
+	    while (rep_len + 1 < sizeof(report_buffer)) {
 		alarm(1);
 		c = get_char();
 		alarm(0);
@@ -1331,8 +1331,10 @@ int get_string(char *string)
 	else {
 	    if (!iscntrl (c)) {
 		int rep_len = strlen (report_buffer);
-		report_buffer[rep_len]     = c;
-		report_buffer[rep_len + 1] = '\0';
+		if (rep_len + 1 < sizeof(report_buffer)) {
+		    report_buffer[rep_len]     = c;
+		    report_buffer[rep_len + 1] = '\0';
+		}
 	    }
 	    else {
 		report_gathering = 0;
```