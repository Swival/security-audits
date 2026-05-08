# final TLV causes out-of-bounds type read

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/mopd/mopprobe/mopprobe.c:302`

## Summary

`mopProcess()` parses attacker-supplied MOP System Information TLVs and unconditionally reads the next TLV type after processing each item. If the final TLV ends exactly at the declared MOP payload boundary, `idx == moplen`, but `mopGetShort(pkt, &idx)` still reads two bytes past the declared packet data before the loop condition is checked again.

A malicious LAN peer can trigger an out-of-bounds read and crash `mopprobe`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an ASan proof of concept using the committed `mopProcess()` and `mopGetShort()` code.

## Preconditions

- `mopprobe` listens on an attacker-reachable LAN interface.
- An attacker can send multicast MOP Remote Console System Information frames.

## Proof

`mopProcess()` accepts multicast `MOP_K_PROTO_RC` System Information frames and derives `moplen` from packet contents.

For Ethernet II frames:

- `moplen` is read from attacker-controlled bytes `pkt[14..15]`.
- `moplen` is converted to an absolute packet offset with `moplen += 16`.
- TLV parsing continues while `idx < moplen`.
- After each TLV body is consumed, the code unconditionally executes `itype = mopGetShort(pkt, &idx)`.

When the final TLV consumes exactly to `moplen`, the loop body leaves `idx == moplen`. The next-type fetch still runs before the next loop-condition check.

`mopGetShort()` unconditionally reads:

```c
pkt[*idx]
pkt[*idx + 1]
```

An ASan PoC confirmed the crash with a 60-byte MOP/RC SID frame using:

- MOP length: `44`
- unknown TLV type
- TLV length: `37`
- value bytes ending at offset `59`

This triggers `heap-buffer-overflow` in `mopGetShort()` called from `usr.sbin/mopd/mopprobe/mopprobe.c:289`.

## Why This Is A Real Bug

The read occurs beyond the declared and captured MOP frame. The attacker controls the frame length and TLV layout sufficiently to place `idx` exactly at `moplen` before the unconditional next-type read.

Because `mopprobe` processes LAN-supplied multicast frames, a malicious peer on the same reachable LAN can crash the process remotely.

## Fix Requirement

Before reading the next TLV type, verify that at least two bytes remain in the declared MOP payload:

```c
idx + 2 <= moplen
```

If fewer than two bytes remain, stop parsing instead of calling `mopGetShort()`.

## Patch Rationale

The patch adds a bounds check immediately before the next-type fetch:

```c
if (idx + 2 > (int)moplen)
	break;
itype = mopGetShort(pkt,&idx);
```

This preserves existing parsing behavior for valid TLV streams while preventing the final-TLV boundary case from reading past the declared MOP payload.

The check is placed at the exact hazardous read site, so it addresses the reproduced crash without changing unrelated TLV handling.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mopd/mopprobe/mopprobe.c b/usr.sbin/mopd/mopprobe/mopprobe.c
index f6fe7f7..5f598e7 100644
--- a/usr.sbin/mopd/mopprobe/mopprobe.c
+++ b/usr.sbin/mopd/mopprobe/mopprobe.c
@@ -286,6 +286,8 @@ mopProcess(struct if_info *ii, u_char *pkt)
 				idx = idx + ilen;
 			};
 		}
+		if (idx + 2 > (int)moplen)
+			break;
 		itype = mopGetShort(pkt,&idx); 
 	}
 }
```