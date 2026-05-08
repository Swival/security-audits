# Software ID Length Overflows Stack Buffer

## Classification

High severity out-of-bounds write.

## Affected Locations

`usr.sbin/mopd/common/dl.c:144`

## Summary

`mopDumpDL()` dumps MOP DL RPR packets and copies the attacker-controlled Software ID into a fixed stack buffer:

- Buffer: `program[17]`
- Length source: packet byte read as `Software ID Len`
- Vulnerable behavior: loop runs for `i < tmpc` without capping `tmpc`
- Impact: stack out-of-bounds write when `Software ID Len > 16`

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `mopDumpDL()` processes an attacker-supplied RPR packet.
- A remote same-L2 MOP peer can send a MOP DL RPR Ethernet frame.
- The packet contains `Software ID Len > 16`.

## Proof

In `usr.sbin/mopd/common/dl.c`, the RPR case declares:

```c
u_char tmpc, c, program[17], code, *ucp;
```

Then reads the Software ID length from the packet:

```c
tmpc = mopGetChar(pkt, &idx);	/* Software ID Len */
for (i = 0; i < tmpc; i++) {
	program[i] = mopGetChar(pkt, &idx);
	program[i + 1] = '\0';
}
```

Because `tmpc` is attacker-controlled and not bounded to `sizeof(program) - 1`:

- With `tmpc == 17`, `program[i + 1] = '\0'` writes `program[17]` out of bounds.
- With `tmpc >= 18`, attacker-controlled bytes are also written past `program[17]`.

Reachability is practical:

- `moptrace` passes received packets directly to `mopDumpDL()` at `usr.sbin/mopd/moptrace/moptrace.c:133`.
- `mopd` reaches `mopDumpDL()` before normal RPR parsing when `DebugFlag >= DEBUG_INFO` at `usr.sbin/mopd/mopd/process.c:358`.
- The later `pfile` length validation at `usr.sbin/mopd/mopd/process.c:388` does not protect this path because it runs after the vulnerable dump call.

## Why This Is A Real Bug

The destination buffer holds 16 Software ID bytes plus a NUL terminator. The loop uses the packet length directly and writes both `program[i]` and `program[i + 1]` on every iteration.

Any packet declaring a Software ID length greater than 16 exceeds the buffer’s capacity. This causes stack memory corruption in the packet dumping worker, with at least attacker-triggered process crash or denial of service risk.

## Fix Requirement

The Software ID copy must not write beyond `program[16]`.

Valid fixes include:

- Rejecting RPR packets with `Software ID Len > sizeof(program) - 1`.
- Truncating the dumped Software ID to `sizeof(program) - 1` while still consuming the full advertised field from the packet.

## Patch Rationale

The patch truncates only the local string copy while preserving packet parsing alignment.

It reads every advertised Software ID byte from the packet, but only stores bytes while `i < sizeof(program) - 1`. This ensures:

- `program` remains NUL-terminated.
- No write occurs beyond the stack buffer.
- `idx` still advances over the full Software ID field.
- Subsequent fields, such as `Processor`, are parsed from the expected position.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mopd/common/dl.c b/usr.sbin/mopd/common/dl.c
index 59d9ce2..4db62b3 100644
--- a/usr.sbin/mopd/common/dl.c
+++ b/usr.sbin/mopd/common/dl.c
@@ -141,8 +141,11 @@ mopDumpDL(FILE *fd, u_char *pkt, int trans)
 		program[0] = 0;
 		tmpc = mopGetChar(pkt, &idx);	/* Software ID Len */
 		for (i = 0; i < tmpc; i++) {
-			program[i] = mopGetChar(pkt, &idx);
-			program[i + 1] = '\0';
+			c = mopGetChar(pkt, &idx);
+			if (i < sizeof(program) - 1) {
+				program[i] = c;
+				program[i + 1] = '\0';
+			}
 		}
 
 		fprintf(fd, "Software     :   %02x '%s'\n", tmpc, program);
```