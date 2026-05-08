# reject path reads uninitialized auth flags

## Classification

Information disclosure, medium severity, CWE-457: Use of Uninitialized Variable.

Confidence: certain.

## Affected Locations

- `usr.sbin/radiusd/radiusd_ipcp.c:718`
- `usr.sbin/radiusd/radiusd_ipcp.c:1035`
- `usr.sbin/radiusd/radiusd_ipcp.c:1069`
- `usr.sbin/radiusd/radiusd_ipcp.c:1073`
- `usr.sbin/radiusd/radiusd_ipcp.c:1075`
- `usr.sbin/radiusd/radiusd_ipcp.c:1079`
- `usr.sbin/radiusd/radiusd.c:730`
- `usr.sbin/radiusd/radiusd.c:1556`

## Summary

`ipcp_reject()` declares `is_mschap` and `is_mschap2` without initialization. If an IPCP rejection path is reached for a request that has no EAP and no Microsoft CHAP attributes, both Microsoft CHAP attribute lookups fail and the flags remain indeterminate. A stale true value enters the MS-CHAP reject branch, where `attr[0] = attr[1]` copies one uninitialized stack byte into an `MS-CHAP-Error` vendor attribute returned in the Access-Reject.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied scanner output, source excerpt, reproducer summary, and patch.

## Preconditions

- A RADIUS Access-Request reaches an IPCP rejection path, such as session quota exhaustion or address pool exhaustion.
- The request does not contain `EAP-Message`.
- The request does not contain Microsoft `MS-CHAP-Response`.
- The request does not contain Microsoft `MS-CHAP2-Response`.

## Proof

`ipcp_resdeco()` rejects quota and pool failures by jumping to `reject`, which calls `ipcp_reject(self, radreq, q_id, radres, msraserr)`.

Inside `ipcp_reject()`:

```c
bool			 is_eap, is_mschap, is_mschap2;
uint8_t			 attr[256];
```

Only `is_eap` is assigned unconditionally:

```c
is_eap = radius_has_attr(reqp, RADIUS_TYPE_EAP_MESSAGE);
```

For a non-MS-CHAP request, both vendor attribute lookups fail:

```c
if (radius_get_vs_raw_attr(reqp, RADIUS_VENDOR_MICROSOFT,
    RADIUS_VTYPE_MS_CHAP_RESPONSE, attr, &attrlen) == 0)
	is_mschap = true;
else if (radius_get_vs_raw_attr(reqp, RADIUS_VENDOR_MICROSOFT,
    RADIUS_VTYPE_MS_CHAP2_RESPONSE, attr, &attrlen) == 0)
	is_mschap2 = true;
```

`is_mschap` and `is_mschap2` are then read while still indeterminate:

```c
} else if (is_mschap || is_mschap2) {
```

If either stale value evaluates true, `attr[0] = attr[1]` copies an uninitialized byte because `attr` was not filled by either failed Microsoft CHAP lookup:

```c
attr[0] = attr[1];
snprintf(attr + 1, sizeof(attr) - 1, "E=%d R=0 V=3", mserr);
radius_put_vs_raw_attr(resp, RADIUS_VENDOR_MICROSOFT,
    RADIUS_VTYPE_MS_CHAP_ERROR, attr, strlen(attr + 1) + 1);
```

The length passed to `radius_put_vs_raw_attr()` includes `attr[0]`, so the uninitialized byte is emitted as the `MS-CHAP-Error` identifier field. The response is returned through `module_resdeco_done()` and then sent to the RADIUS client.

## Why This Is A Real Bug

This is not a theoretical uninitialized read. The attacker controls the trigger by sending an Access-Request that lacks EAP and Microsoft CHAP attributes while causing an IPCP reject condition such as session or pool exhaustion. The code then reads uninitialized boolean flags and can serialize one uninitialized stack byte into the Access-Reject response. That is externally observable by the malicious RADIUS client as an information disclosure.

## Fix Requirement

Initialize `is_mschap` and `is_mschap2` to `false` before the Microsoft CHAP attribute checks. The reject path must only enter the MS-CHAP error construction branch when a corresponding request attribute was actually present and copied into `attr`.

## Patch Rationale

The patch changes the declaration from uninitialized booleans to explicit false defaults:

```c
bool			 is_eap, is_mschap = false, is_mschap2 = false;
```

This preserves existing behavior for real MS-CHAP and MS-CHAPv2 requests because successful attribute lookups still set the corresponding flag to `true`. For non-MS-CHAP requests, both flags remain `false`, preventing the branch that reads `attr[1]` and emits `attr[0]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/radiusd/radiusd_ipcp.c b/usr.sbin/radiusd/radiusd_ipcp.c
index 3c8715b..9b63840 100644
--- a/usr.sbin/radiusd/radiusd_ipcp.c
+++ b/usr.sbin/radiusd/radiusd_ipcp.c
@@ -1032,7 +1032,7 @@ void
 ipcp_reject(struct module_ipcp *self, RADIUS_PACKET *reqp, unsigned int q_id,
     RADIUS_PACKET *orig_resp, int mserr)
 {
-	bool			 is_eap, is_mschap, is_mschap2;
+	bool			 is_eap, is_mschap = false, is_mschap2 = false;
 	uint8_t			 attr[256];
 	size_t			 attrlen;
 	RADIUS_PACKET		*resp;
```