# unchecked MOP info length overreads packet data

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/mopd/common/print.c:612`

Primary vulnerable read path also reaches `usr.sbin/mopd/common/print.c:639`.

## Summary

`mopPrintInfo()` trusts an attacker-controlled MOP information-item length byte before printing unknown information items. If the declared item length exceeds the remaining declared MOP payload, the packet printer advances past the payload boundary and reads/emits bytes beyond the packet data.

The patch rejects malformed items whose `ilen` is larger than the remaining declared MOP payload before any item-specific parsing or printing occurs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied scanner result, source excerpt, reproducer summary, and patch.

## Preconditions

- `mopPrintInfo()` is invoked on an attacker-supplied MOP frame.
- The frame contains an information item with an unknown type.
- The item length byte, `ilen`, is larger than the remaining declared MOP payload.

## Proof

The reproduced path is:

- `mopPrintInfo()` derives `moplen` from the frame header.
- The parser reads attacker-controlled `ilen` using `mopGetChar()`.
- For unknown information types, it sets `ucp = pkt + *idx`.
- It advances `*idx` by `ilen`.
- It then prints `ucp[i]` for every `i < ilen`.

This occurs without checking whether `ilen` fits within the remaining declared MOP payload.

The issue was reproduced with a crafted Ethernet MOP RPR frame declaring a 9-byte MOP payload where the unknown information item uses `ilen = 0xff`. ASan reported a heap-buffer-overflow read at `usr.sbin/mopd/common/print.c:639`.

A non-ASan harness with controlled bytes placed after the declared payload printed those bytes, including `de ad be ef`, confirming the overread-and-emit behavior.

Remote reachability was confirmed through:

- `usr.sbin/mopd/moptrace/moptrace.c:133`, where `moptrace` prints received frames.
- `usr.sbin/mopd/mopd/process.c:358`, where `mopd -ddd` debug printing invokes the packet printer.

## Why This Is A Real Bug

The parser uses `ilen` as an authoritative byte count for later reads, but `ilen` is attacker-controlled packet data. The loop condition only checks `*idx < moplen + 2` before reading the item length; it does not prove that the full item body is present.

For unknown information types, the code reads `ilen` bytes from `ucp` during output. If fewer than `ilen` bytes remain in the declared MOP payload, this reads beyond the packet’s declared data and can disclose adjacent memory through diagnostic output or trigger a memory-safety fault.

The ASan heap-buffer-overflow and non-ASan leaked sentinel bytes confirm both invalid memory access and observable data emission.

## Fix Requirement

Before advancing `*idx` or printing item data, validate that `ilen` does not exceed the number of bytes remaining before `moplen + 2`.

Malformed items must be rejected or clamped. Rejecting is sufficient and safer because it avoids parsing a truncated item as valid data.

## Patch Rationale

The patch adds a single bounds check immediately after reading `ilen`:

```c
if (ilen > (moplen + 2) - *idx)
	return;
```

At that point, `*idx` has already advanced past the length byte and points at the item body. Therefore `(moplen + 2) - *idx` is the remaining declared payload available for the item body.

Returning prevents all later switch cases from reading, advancing, or printing beyond the declared MOP payload. This protects the unknown-type path described in the finding and also blocks the same malformed-length condition before other item-specific handlers process the item.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mopd/common/print.c b/usr.sbin/mopd/common/print.c
index 13df7d8..fbcb2a2 100644
--- a/usr.sbin/mopd/common/print.c
+++ b/usr.sbin/mopd/common/print.c
@@ -440,6 +440,8 @@ mopPrintInfo(FILE *fd, u_char *pkt, int *idx, u_short moplen, u_char mopcode,
 
 	while (*idx < (moplen + 2)) {
 		ilen = mopGetChar(pkt, idx);
+		if (ilen > (moplen + 2) - *idx)
+			return;
 		switch (itype) {
 		case 0:
 			tmpc  = mopGetChar(pkt, idx);
```