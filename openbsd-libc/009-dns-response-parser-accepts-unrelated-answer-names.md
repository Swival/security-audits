# DNS response parser accepts unrelated answer names

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`asr/getaddrinfo_async.c:593`

## Summary

`addrinfo_from_pkt()` accepted DNS answer records based only on matching RR type and class. It did not require the answer owner name to match the queried name, allowing an attacker-controlled or spoofed DNS response to supply an unrelated A/AAAA record that is returned as the address for the victim hostname.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Victim resolves through an attacker-controlled DNS responder or a DNS response path that can be spoofed.

## Proof

`addrinfo_from_pkt()` unpacks the DNS response, stores the question in `q`, then iterates `h.ancount` answer RRs. Before the patch, the acceptance check only required:

```c
if (rr.rr_type != q.q_type ||
    rr.rr_class != q.q_class)
        continue;
```

After that check, matching A or AAAA RDATA was converted into a sockaddr and appended to the `getaddrinfo()` result with `addrinfo_add()`.

The reproduced data confirms lower-level validation does not block this: `validate_packet()` checks transaction ID, response flags, one question, and that the question matches the original query, but it only unpacks answer RRs for validity and does not validate answer owner names. Therefore a malicious answer such as an A record for `attacker.example.` with the queried type/class can be returned for `victim.example.`.

## Why This Is A Real Bug

DNS answer ownership is semantically significant. An A or AAAA record for an unrelated owner name is not an address for the queried hostname merely because its type and class match. Accepting such records lets a malicious or spoofing responder inject attacker-chosen addresses into `getaddrinfo("victim.example")`, causing callers to connect to the wrong host.

## Fix Requirement

Each accepted answer RR must have an owner name matching the queried canonical DNS name before its RDATA is converted into an address and passed to `addrinfo_add()`.

## Patch Rationale

The patch extends the existing answer filter in `addrinfo_from_pkt()` to also compare `rr.rr_dname` with `q.q_dname` case-insensitively:

```c
if (rr.rr_type != q.q_type ||
    rr.rr_class != q.q_class ||
    strcasecmp(rr.rr_dname, q.q_dname))
        continue;
```

DNS names are case-insensitive, so `strcasecmp()` is appropriate. This preserves valid answers for the queried name while rejecting unrelated owner names even when type and class match.

## Residual Risk

None

## Patch

```diff
diff --git a/asr/getaddrinfo_async.c b/asr/getaddrinfo_async.c
index b24c1e3..07bfb02 100644
--- a/asr/getaddrinfo_async.c
+++ b/asr/getaddrinfo_async.c
@@ -658,7 +658,8 @@ addrinfo_from_pkt(struct asr_query *as, char *pkt, size_t pktlen)
 	for (i = 0; i < h.ancount; i++) {
 		_asr_unpack_rr(&p, &rr);
 		if (rr.rr_type != q.q_type ||
-		    rr.rr_class != q.q_class)
+		    rr.rr_class != q.q_class ||
+		    strcasecmp(rr.rr_dname, q.q_dname))
 			continue;
 
 		memset(&u, 0, sizeof u);
```