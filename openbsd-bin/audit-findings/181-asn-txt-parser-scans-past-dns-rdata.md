# ASN TXT parser scans past DNS rdata

## Classification

Medium severity out-of-bounds read.

## Affected Locations

`usr.sbin/traceroute/worker.c:1198`

## Summary

`traceroute` ASN lookup parsing treats DNS TXT RDATA as a NUL-terminated string. DNS TXT RDATA is length-prefixed and may contain no NUL byte. A malicious DNS responder can return a valid TXT RDATA without `|` or NUL, causing `strchr()` to scan past the allocated RDATA buffer.

## Provenance

Verified and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- `traceroute` runs with ASN lookup enabled.
- The process accepts a responder-controlled TXT answer for the Cymru ASN lookup.

## Proof

`print_asn()` issues a `T_TXT` lookup for the Cymru ASN name at `usr.sbin/traceroute/worker.c:958`.

In `getrrsetbyname_async_done()`, each `answers->rri_rdatas[counter].rdi_data` is DNS TXT RDATA: one length byte followed by length-delimited TXT bytes.

The vulnerable parser does:

```c
char *p, *as = answers->rri_rdatas[counter].rdi_data;
as++; /* skip first byte, it contains length */
if ((p = strchr(as,'|'))) {
```

A malicious TXT RDATA such as:

```text
0x01 '1'
```

is valid length-prefixed TXT data with declared length 1 and no NUL terminator. Because `strchr(as, '|')` ignores `rdi_length`, it reads beyond the RDATA allocation while searching for `|` or NUL.

The reproducer confirmed this with an ASan harness using `rdi_length=2` and `rdi_data={0x01,'1'}`. ASan reports a heap-buffer-overflow read in `strchr()` at the callback.

## Why This Is A Real Bug

DNS TXT RDATA is not C string data. It is length-delimited wire data. The callback receives both `rdi_data` and `rdi_length`, but the vulnerable code discards the length and uses `strchr()`, which requires a NUL-terminated string.

This makes the read boundary dependent on adjacent heap contents rather than the DNS RDATA length. If adjacent memory contains `|`, the code may also write through `p[-1]` and copy bytes outside the TXT payload into the ASN output. At minimum, this is attacker-triggered memory-safety denial-of-service risk.

## Fix Requirement

Parse TXT RDATA using `rdi_length` and bounded searches only. Do not call C string functions on DNS RDATA unless the data has first been validated and copied into a NUL-terminated buffer.

## Patch Rationale

The patch validates that the RDATA contains at least the TXT length byte, derives the TXT payload length from that byte, caps it to the available `rdi_length - 1`, and replaces unbounded `strchr()` with bounded `memchr()`.

It also removes the in-place `p[-1] = 0` mutation and formats the ASN using a precision-limited `%.*s`, so output construction does not require NUL termination and cannot read beyond the bounded TXT field.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/traceroute/worker.c b/usr.sbin/traceroute/worker.c
index 0865f4d..f2c5e56 100644
--- a/usr.sbin/traceroute/worker.c
+++ b/usr.sbin/traceroute/worker.c
@@ -1203,11 +1203,18 @@ getrrsetbyname_async_done(struct asr_result *ar, void *arg)
 
 	for (counter = 0; counter < answers->rri_nrdatas; counter++) {
 		char *p, *as = answers->rri_rdatas[counter].rdi_data;
+		size_t aslen;
+
+		if (answers->rri_rdatas[counter].rdi_length < 1)
+			continue;
+		aslen = (u_char)*as;
+		if (aslen > answers->rri_rdatas[counter].rdi_length - 1)
+			aslen = answers->rri_rdatas[counter].rdi_length - 1;
 		as++; /* skip first byte, it contains length */
-		if ((p = strchr(as,'|'))) {
-			p[-1] = 0;
-			len = snprintf(asn, asn_size, "%sAS%s",
-			    counter ? ", " : "[", as);
+		if ((p = memchr(as, '|', aslen)) != NULL) {
+			len = snprintf(asn, asn_size, "%sAS%.*s",
+			    counter ? ", " : "[",
+			    p > as ? (int)(p - as - 1) : 0, as);
 			if (len != -1 && len < asn_size) {
 				asn += len;
 				asn_size -= len;
```