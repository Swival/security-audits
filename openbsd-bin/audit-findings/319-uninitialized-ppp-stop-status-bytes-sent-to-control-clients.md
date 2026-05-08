# Uninitialized PPP_STOP Status Bytes Sent To Control Clients

## Classification

Information disclosure, medium severity, confirmed.

## Affected Locations

`usr.sbin/npppd/npppd/npppd_ctl.c:198`

## Summary

`npppd_ctl_add_stopped_ppp()` allocates a `struct stopped_ppp` with `malloc()` and initializes only selected fields of its embedded `struct npppd_who`. When a PPP session stops, `npppd_ctl_imsg_compose()` serializes the entire `struct npppd_who` into an `IMSG_PPP_STOP` response. Any padding, trailing fixed-size string bytes, or untouched union/storage bytes can therefore disclose prior daemon heap contents to a control-monitoring client.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A client can access npppd control monitoring.
- A PPP session stops while that client is monitoring PPP status.

## Proof

`npppd_ctl_add_stopped_ppp()` allocates `struct stopped_ppp` with `malloc()` and immediately calls:

```c
npppd_who_init(&stopped->ppp_who, ppp);
```

The destination object is not cleared first.

`npppd_who_init()` assigns selected scalar fields and copies strings with `strlcpy()`. `strlcpy()` NUL-terminates the string but does not clear the remaining bytes in the fixed-size destination buffer. The function also only initializes part of `tunnel_peer` before conditionally copying `ppp->phy_info`, leaving unused bytes possible.

Later, `npppd_ctl_imsg_compose()` copies the whole object:

```c
memcpy(&who_list->entry[cnt], &e->ppp_who,
    sizeof(who_list->entry[0]));
```

It then sends:

```c
imsg_compose(ibuf, IMSG_PPP_STOP, 0, 0, -1, pktbuf,
    offsetof(struct npppd_who_list, entry[cnt]))
```

A custom control client can inspect the raw `IMSG_PPP_STOP` payload and recover uninitialized bytes embedded in the serialized `struct npppd_who`.

## Why This Is A Real Bug

The data sent to the control client is not limited to the meaningful initialized fields. It includes the complete binary representation of `struct npppd_who`, including padding and unused portions of fixed-size fields. Because the source object is malloc-backed and not zeroed before partial initialization, those bytes can contain stale daemon heap data.

The issue is specific to stopped PPP status entries because they are first stored in heap-allocated `struct stopped_ppp` objects before being serialized.

## Fix Requirement

Clear the serialized `struct npppd_who` storage before calling `npppd_who_init()`, or otherwise guarantee that `npppd_who_init()` fully initializes every byte that can be transmitted.

## Patch Rationale

The patch zeroes `stopped->ppp_who` immediately after successful allocation and before field initialization:

```c
memset(&stopped->ppp_who, 0, sizeof(stopped->ppp_who));
npppd_who_init(&stopped->ppp_who, ppp);
```

This preserves all intended field assignments while ensuring any padding, trailing string capacity, or unused storage bytes serialize as zeroes instead of stale heap contents.

## Residual Risk

None.

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/npppd_ctl.c b/usr.sbin/npppd/npppd/npppd_ctl.c
index e67e568..8c53b81 100644
--- a/usr.sbin/npppd/npppd/npppd_ctl.c
+++ b/usr.sbin/npppd/npppd/npppd_ctl.c
@@ -151,6 +151,7 @@ npppd_ctl_add_stopped_ppp(struct npppd_ctl *_this, npppd_ppp *ppp)
 		log_warn("malloc() failed in %s()", __func__);
 		return (-1);
 	}
+	memset(&stopped->ppp_who, 0, sizeof(stopped->ppp_who));
 	npppd_who_init(&stopped->ppp_who, ppp);
 	TAILQ_INSERT_TAIL(&_this->stopped_ppps, stopped, entry);
```