# Short MPPE Frame Bypasses Minimum Length Check

## Classification

Out-of-bounds read, high severity.

## Affected Locations

`usr.sbin/npppd/npppd/mppe.c:321`

## Summary

`mppe_input()` documents that MPPE input length must be at least 4 bytes, but the minimum-length validation is enforced only by `MPPE_ASSERT(len >= 4)`. In non-`MPPE_DEBUG` builds, `MPPE_ASSERT` expands to nothing, so a remote PPP peer can send a short MPPE frame that reaches fixed-width reads and decryption using an invalid negative payload length.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- MPPE is negotiated.
- Assertions are disabled by building without `MPPE_DEBUG`.
- An attacker controls a remote established PPP peer that can send MPPE packets.

## Proof

A malicious peer can send the PPP frame bytes:

```text
ff 03 00 fd 90
```

This consists of ACF, protocol `PPP_PROTO_MPPE`, and a 1-byte MPPE body.

The outer PPP receive path only requires the full PPP frame to be at least 4 bytes, strips the ACF/protocol fields, and calls `mppe_input()` with the remaining MPPE body length. This input reaches `mppe_input(..., len=1)`.

In `mppe_input()`:

- The documented requirement says `len must be 4 at least`.
- `MPPE_ASSERT(len >= 4)` compiles away when `MPPE_DEBUG` is not defined.
- `GETSHORT(coher_cnt, pktp)` reads two bytes from a 1-byte MPPE body.
- The attacker-controlled byte `0x90` sets the flushed and encrypted bits, allowing processing to continue.
- `mppe_rc4_encrypt(_this, &_this->recv, len - 2, pktp, pktp)` is then called with `len - 2 == -1`.
- The OpenSSL RC4 API receives that negative length as a huge unsigned length, causing out-of-bounds memory access and a practical remote daemon crash.

## Why This Is A Real Bug

This is a runtime validation bug, not a debug-only assertion failure. The function accepts peer-supplied packet length, but the only minimum-length guard is removed from normal builds. The remaining code unconditionally performs reads and decryption that require at least 4 bytes of MPPE data. The reproduced 1-byte MPPE body passes the outer PPP framing checks and reaches the vulnerable path.

## Fix Requirement

Reject `len < 4` at the start of `mppe_input()` before reading `pktp`, parsing the coherency counter, decrypting payload, or inspecting decrypted protocol bytes.

## Patch Rationale

The patch replaces the debug-only assertion with an unconditional runtime guard:

```c
if (len < 4)
	return;
```

This preserves the documented minimum MPPE frame size and prevents short peer-controlled buffers from reaching `GETSHORT()`, `mppe_rc4_encrypt(len - 2, ...)`, and subsequent protocol parsing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/mppe.c b/usr.sbin/npppd/npppd/mppe.c
index 12e5843..a315f24 100644
--- a/usr.sbin/npppd/npppd/mppe.c
+++ b/usr.sbin/npppd/npppd/mppe.c
@@ -320,7 +320,8 @@ mppe_input(mppe *_this, u_char *pktp, int len)
 	encrypt = 0;
 	flushed = 0;
 
-	MPPE_ASSERT(len >= 4);
+	if (len < 4)
+		return;
 
 	pktp0 = pktp;
 	GETSHORT(coher_cnt, pktp);
```