# Unterminated OACK Value Reaches strlen

## Classification

Out-of-bounds read, denial of service.

Confidence: certain.

## Affected Locations

`usr.bin/tftp/tftp.c:620`

## Summary

A malicious TFTP server can send an OACK packet whose option name is NUL-terminated but whose option value is not. The client parses the option name within packet bounds, then treats the value as a C string and calls `strlen(val)`. If the value has no NUL byte inside the received packet, `strlen` reads past the packet buffer and may crash the client.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an ASAN harness using the committed `oack()` logic and a malformed OACK payload containing a NUL option name followed by an unterminated value.

## Preconditions

- The client receives an OACK packet from the transfer server.
- The transfer peer is malicious or compromised.
- The OACK payload contains a terminated option name followed by a value without a NUL terminator before the end of the received packet.

## Proof

`recvfile()` receives attacker-controlled UDP data into `dp` and calls `oack(dp, n, 0)` when the packet opcode is `OACK`.

`sendfile()` has the same OACK processing path via `ackbuf`.

Inside `oack()`:

- `val` starts at the OACK payload.
- The loop bounds the scan for the option-name NUL with `i < size - 1`.
- After finding the option-name NUL, the code increments `val` to the value.
- The original code then calls `strlen(val)` without first proving that the value is NUL-terminated inside the received packet.

A malformed OACK payload of the form `"\0AAAA..."` with no value terminator reaches `strlen(val)` and causes ASAN to report a heap-buffer-overflow.

## Why This Is A Real Bug

The UDP packet length `n` is known, but the value string is parsed with unbounded C-string logic. Network input is not guaranteed to contain a NUL terminator. Therefore `strlen(val)` can continue reading beyond the received packet buffer until it finds an unrelated NUL byte or faults.

This is reachable from both download and upload option-negotiation paths and gives a malicious TFTP peer a practical client crash primitive.

## Fix Requirement

Parse OACK option/value fields using packet-length-bounded searches. Reject or stop parsing when either the option name or option value is not NUL-terminated within the received packet.

## Patch Rationale

The patch replaces the unbounded `strlen(val)` length calculation with a bounded `memchr(val, '\0', size - i - 1)` search.

This ensures the parser only accepts a value terminator that exists within the remaining received packet bytes. If no terminator is found, parsing stops before `printf("%s=%s", opt, val)`, `oack_set(opt, val)`, or any length calculation can consume the unterminated value as a C string.

The resulting `len = end - val + 1` preserves existing behavior for well-formed OACK fields while preventing reads past `size`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/tftp/tftp.c b/usr.bin/tftp/tftp.c
index 265f51e..56f6a0e 100644
--- a/usr.bin/tftp/tftp.c
+++ b/usr.bin/tftp/tftp.c
@@ -583,7 +583,7 @@ static void
 oack(struct tftphdr *tp, int size, int trace)
 {
 	int	 i, len, off;
-	char	*opt, *val;
+	char	*end, *opt, *val;
 
 	u_short op = ntohs(tp->th_opcode);
 
@@ -611,12 +611,14 @@ oack(struct tftphdr *tp, int size, int trace)
 		}
 		/* got option and value */
 		val++;
+		if ((end = memchr(val, '\0', size - i - 1)) == NULL)
+			break;
+		len = end - val + 1;
 		if (trace)
 			printf("%s=%s", opt, val);
 		else
 			if (oack_set(opt, val) == -1)
 				break;
-		len = strlen(val) + 1;
 		val += len;
 		opt = val;
 		i += len;
```