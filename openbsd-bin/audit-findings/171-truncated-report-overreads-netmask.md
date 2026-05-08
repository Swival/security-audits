# truncated report overreads netmask

## Classification

Out-of-bounds read, high severity.

## Affected Locations

`usr.sbin/dvmrpd/report.c:97`

## Summary

`recv_report()` accepts DVMRP report payloads from 2-WAY or compat neighbors, then enters a `do` loop and reads fixed-width fields before proving the packet contains those bytes. A truncated report can make the daemon read past the received packet buffer while parsing the netmask, route netid, or metric.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker is a malicious established DVMRP neighbor, or a compat sender accepted by the state gate.
- The neighbor sends a truncated DVMRP report payload.
- The payload is shorter than the parser’s next fixed-width read.

## Proof

`recv_report()` only checks neighbor state before parsing. For a 2-WAY neighbor, or a compat neighbor, execution reaches the report parser.

The parser uses a `do` loop, so it parses at least once even when `len == 0`. It then unconditionally performs:

```c
memcpy(&netmask, buf, sizeof(netmask));
```

This reads four bytes from `buf` even when the attacker-controlled report length is less than four bytes.

After the netmask read, the parser advances:

```c
buf += 3;
len -= 3;
```

Because `len` is `u_int16_t`, truncated inputs can underflow the remaining length. Subsequent fixed-width reads of `netid` and `metric` can therefore continue beyond the received packet buffer.

The issue was reproduced with an ASan harness using the committed `recv_report()` logic, `READ_BUF_SIZE == 65535`, a 2-WAY neighbor, `buf = recv_buf + 28`, and `len = 0`. ASan reported a heap-buffer-overflow read of size 4 at the byte after the allocated receive buffer.

## Why This Is A Real Bug

The packet length is attacker-controlled after the neighbor state gate, and the first parser iteration happens regardless of length. A truncated report therefore deterministically reaches a four-byte `memcpy()` without a prior `len >= 4` check.

The impact is concrete: an accepted malicious DVMRP neighbor can crash the daemon through an out-of-bounds read, causing denial of service.

## Fix Requirement

Before each fixed-width field read, verify that the remaining payload length is sufficient:

- Require `len >= sizeof(netmask)` before reading the netmask.
- Require `len >= sizeof(netid)` before reading the netid.
- Require `len >= sizeof(metric)` before reading the metric.

Parsing must stop before advancing `buf` or subtracting from `len` when the required bytes are unavailable.

## Patch Rationale

The patch adds length guards immediately before each vulnerable `memcpy()` in `recv_report()`.

This ensures truncated reports return before any out-of-bounds read occurs. The checks are placed at the actual read sites, so they protect all parser paths, including the mandatory first `do` loop iteration and any later iterations reached after length arithmetic.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dvmrpd/report.c b/usr.sbin/dvmrpd/report.c
index b961a52..80a5590 100644
--- a/usr.sbin/dvmrpd/report.c
+++ b/usr.sbin/dvmrpd/report.c
@@ -97,6 +97,8 @@ recv_report(struct nbr *nbr, char *buf, u_int16_t len)
 		 */
 
 		/* read four bytes */
+		if (len < sizeof(netmask))
+			return;
 		memcpy(&netmask, buf, sizeof(netmask));
 		/* ditch one byte, since we only need three */
 		netmask = ntohl(netmask) >> 8;
@@ -119,6 +121,8 @@ recv_report(struct nbr *nbr, char *buf, u_int16_t len)
 			 * Read 4 bytes and use the netmask from above to
 			 * determine the netid.
 			 */
+			if (len < sizeof(netid))
+				return;
 			memcpy(&netid, buf, sizeof(netid));
 			netid &= netmask;
 
@@ -126,6 +130,8 @@ recv_report(struct nbr *nbr, char *buf, u_int16_t len)
 			len -= netid_len;
 
 			/* get metric */
+			if (len < sizeof(metric))
+				return;
 			memcpy(&metric, buf, sizeof(metric));
 			buf += sizeof(metric);
 			len -= sizeof(metric);
```