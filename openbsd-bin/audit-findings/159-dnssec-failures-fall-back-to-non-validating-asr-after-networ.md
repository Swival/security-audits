# DNSSEC BOGUS Responses Fall Back To Non-Validating ASR

## Classification

High-severity policy bypass. Confidence: certain.

## Affected Locations

- `sbin/unwind/resolver.c:982`
- `sbin/unwind/resolver.c:1027`
- `sbin/unwind/resolver.c:1073`
- `sbin/unwind/resolver.c:1674`
- `sbin/unwind/frontend.c:551`
- `sbin/unwind/frontend.c:571`

## Summary

Within five minutes of a network change, `unwind` treated both DNSSEC `BOGUS` answers and `NXDOMAIN` answers as doubtful captive-portal indicators. That retry path could redirect a DNSSEC-invalid answer from a validating resolver to ASR, which is non-validating. The later ASR response arrived with `sec=0`, skipped bogus handling, cleared `answer_header->bogus`, and was sent to clients instead of being converted to SERVFAIL.

## Provenance

Reported and reproduced from a Swival Security Scanner finding: https://swival.dev

## Preconditions

- ASR resolver is configured.
- ASR resolver is available after a recent network change.
- A DNSSEC-validating resolver first returns a DNSSEC `BOGUS` result.
- The query occurs within `DOUBT_NXDOMAIN_SEC`, the five-minute post-network-change window.

## Proof

The vulnerable branch in `resolve_done()` checked:

```c
if (sec != SECURE && elapsed.tv_sec < DOUBT_NXDOMAIN_SEC &&
    !force_acceptbogus && res->type != UW_RES_ASR &&
    (result->rcode == LDNS_RCODE_NXDOMAIN || sec == BOGUS)) {
```

For a DNSSEC `BOGUS` response from a validating resolver, this branch searched `rq->res_pref` for `UW_RES_ASR`, rewound `rq->next_resolver`, and called `try_next_resolver()`.

ASR completion always invoked the resolver callback with `sec=0`:

```c
cb_data->cb(..., ar->ar_data, ar->ar_datalen, 0, NULL);
```

Because ASR is non-validating and `res->type == UW_RES_ASR`, the later ASR answer skipped the doubt branch. Since bogus marking only occurs when `res->state == VALIDATING && sec == BOGUS`, the ASR answer set:

```c
answer_header->bogus = 0;
```

The frontend only converts DNSSEC-bogus answers to SERVFAIL when `answer_header->bogus` is set. The ASR retry therefore caused unsigned or forged ASR data to reach clients.

## Why This Is A Real Bug

DNSSEC `BOGUS` is an integrity failure, not an availability ambiguity. Retrying a DNSSEC-invalid result through a non-validating resolver changes the security decision from “reject” to “accept unsigned data.” A malicious local-network DNS server can exploit the post-network-change window by returning DNSSEC-invalid data for a signed victim domain, then supplying a forged ASR response. The client receives spoofed DNS data instead of SERVFAIL.

## Fix Requirement

Never retry DNSSEC `BOGUS` responses through non-validating ASR. The captive-portal doubt fallback may remain for non-secure `NXDOMAIN` handling, but DNSSEC validation failures must preserve the validating resolver’s rejection semantics.

## Patch Rationale

The patch removes `sec == BOGUS` from the doubt fallback and explicitly excludes `BOGUS` from the branch condition:

```diff
-if (sec != SECURE && elapsed.tv_sec < DOUBT_NXDOMAIN_SEC &&
+if (sec != SECURE && sec != BOGUS &&
+    elapsed.tv_sec < DOUBT_NXDOMAIN_SEC &&
     !force_acceptbogus && res->type != UW_RES_ASR &&
-    (result->rcode == LDNS_RCODE_NXDOMAIN || sec == BOGUS)) {
+    result->rcode == LDNS_RCODE_NXDOMAIN) {
```

This preserves the intended post-network-change `NXDOMAIN` doubt behavior while ensuring DNSSEC `BOGUS` results continue into the existing bogus-marking path and are rejected by the frontend as SERVFAIL.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/resolver.c b/sbin/unwind/resolver.c
index d026bb0..bea5800 100644
--- a/sbin/unwind/resolver.c
+++ b/sbin/unwind/resolver.c
@@ -1027,9 +1027,10 @@ resolve_done(struct uw_resolver *res, void *arg, int rcode,
 		force_acceptbogus = 0;
 
 	timespecsub(&tp, &last_network_change, &elapsed);
-	if (sec != SECURE && elapsed.tv_sec < DOUBT_NXDOMAIN_SEC &&
+	if (sec != SECURE && sec != BOGUS &&
+	    elapsed.tv_sec < DOUBT_NXDOMAIN_SEC &&
 	    !force_acceptbogus && res->type != UW_RES_ASR &&
-	    (result->rcode == LDNS_RCODE_NXDOMAIN || sec == BOGUS)) {
+	    result->rcode == LDNS_RCODE_NXDOMAIN) {
 		/*
 		 * Doubt NXDOMAIN or BOGUS if we just switched networks, we
 		 * might be behind a captive portal.
```