# Truncated Route Entry Overreads Netid

## Classification

Out-of-bounds read, high severity.

## Affected Locations

`usr.sbin/dvmrpd/report.c:120`

## Summary

`recv_report()` parses DVMRP route reports from accepted neighbors without validating that enough report bytes remain before fixed-size reads. A malicious established DVMRP neighbor can send a four-byte report body that satisfies the initial netmask read but leaves only one byte before the parser unconditionally reads a four-byte `netid`, causing a three-byte overread past the received packet buffer.

## Provenance

Verified from the provided affected source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The sender is a DVMRP neighbor in `NBR_STA_2_WAY`; or
- Compatibility mode accepts the report source via `nbr->compat`.

## Proof

Packet handling accepts DVMRP report packets from an existing neighbor, or creates a compatibility neighbor for unknown report sources, then calls `recv_report(nbr, buf, len)` without validating the report-body structure.

`recv_report()` only gates parsing on the neighbor state or compatibility flag:

```c
if ((nbr->state != NBR_STA_2_WAY) && (!nbr->compat)) {
        ...
        return;
}
```

With a four-byte report body:

1. `memcpy(&netmask, buf, sizeof(netmask))` reads four bytes.
2. The parser advances by only three bytes because the DVMRP netmask is encoded as three bytes:
   ```c
   buf += 3;
   len -= 3;
   ```
3. `len` is now `1`.
4. The inner `do` loop runs unconditionally.
5. `memcpy(&netid, buf, sizeof(netid))` reads four bytes while only one byte remains.

This produces a three-byte out-of-bounds read past the packet buffer. The subsequent unsigned length subtraction can also underflow, extending the malformed parse path.

## Why This Is A Real Bug

The parser performs memory reads based on protocol fields before checking the remaining packet length. The triggering packet is reachable from a malicious established DVMRP neighbor or compatibility-accepted source, and the four-byte payload is sufficient to enter the vulnerable path. Because `memcpy(&netid, buf, sizeof(netid))` requires four readable bytes but only one remains, the behavior is an attacker-triggered memory-safety violation and potential daemon crash or denial of service.

## Fix Requirement

Validate the remaining length before every parser read:

- Require at least `sizeof(netmask)` before reading the initial netmask.
- Require at least the encoded `netid_len` before reading the route network ID.
- Require at least `sizeof(metric)` before reading the metric.
- Avoid fixed four-byte reads for variable-length `netid` fields.

## Patch Rationale

The patch adds explicit length checks immediately before each read and changes the `netid` copy to match the protocol-encoded length:

```c
if (len < sizeof(netmask))
        return;
```

```c
if (len < netid_len)
        return;
netid = 0;
memcpy(&netid, buf, netid_len);
```

```c
if (len < sizeof(metric))
        return;
```

This prevents truncated report bodies from being parsed past their received buffer and avoids the original four-byte `netid` read when fewer encoded bytes are present. Initializing `netid` before the shorter copy ensures unused bytes are deterministic before applying the netmask.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dvmrpd/report.c b/usr.sbin/dvmrpd/report.c
index b961a52..95f8f00 100644
--- a/usr.sbin/dvmrpd/report.c
+++ b/usr.sbin/dvmrpd/report.c
@@ -96,6 +96,8 @@ recv_report(struct nbr *nbr, char *buf, u_int16_t len)
 		 * The most significant part of the mask is always 255.
 		 */
 
+		if (len < sizeof(netmask))
+			return;
 		/* read four bytes */
 		memcpy(&netmask, buf, sizeof(netmask));
 		/* ditch one byte, since we only need three */
@@ -116,16 +118,19 @@ recv_report(struct nbr *nbr, char *buf, u_int16_t len)
 			 *
 			 * The length of the netid is depending on the above
 			 * netmask.
-			 * Read 4 bytes and use the netmask from above to
-			 * determine the netid.
 			 */
-			memcpy(&netid, buf, sizeof(netid));
+			if (len < netid_len)
+				return;
+			netid = 0;
+			memcpy(&netid, buf, netid_len);
 			netid &= netmask;
 
 			buf += netid_len;
 			len -= netid_len;
 
 			/* get metric */
+			if (len < sizeof(metric))
+				return;
 			memcpy(&metric, buf, sizeof(metric));
 			buf += sizeof(metric);
 			len -= sizeof(metric);
```