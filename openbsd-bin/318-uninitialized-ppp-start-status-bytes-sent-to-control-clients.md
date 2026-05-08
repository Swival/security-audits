# Uninitialized PPP_START Status Bytes Sent To Control Clients

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

- `usr.sbin/npppd/npppd/npppd_ctl.c:218`
- `usr.sbin/npppd/npppd/npppd_ctl.c:246`
- `usr.sbin/npppd/npppd/npppd_ctl.c:265`

## Summary

`npppd_ctl_imsg_compose()` builds `IMSG_PPP_START` responses in a stack buffer and serializes full `struct npppd_who` entries to control clients. Each entry is populated by `npppd_who_init()`, but that function previously initialized only selected fields. Padding, trailing bytes in fixed-size string arrays, and union tail bytes could therefore retain daemon stack contents and be sent to a local control client requesting `who` output.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A local control client can request `who` output from `npppd`.
- At least one active PPP session exists, so the `IMSG_PPP_START` response contains one or more `struct npppd_who` entries.

## Proof

`npppd_ctl_who0()` marks the control connection as responding and walks active PPP sessions into `started_ppp`.

During response construction, `npppd_ctl_imsg_compose()` declares an uninitialized stack buffer:

```c
u_char pktbuf[MAX_IMSGSIZE - IMSG_HEADER_SIZE];
```

It casts that buffer to `struct npppd_who_list *` and fills entries with:

```c
npppd_who_init(&who_list->entry[cnt], ppp);
```

Before the patch, `npppd_who_init()` assigned scalar fields and used `strlcpy()` for fixed-size strings, but it did not clear the full destination object. This left bytes not explicitly written by the field assignments unchanged from `pktbuf` stack contents.

The response is then serialized with:

```c
imsg_compose(ibuf, IMSG_PPP_START, 0, 0, -1, pktbuf,
    offsetof(struct npppd_who_list, entry[cnt]))
```

That length includes complete `struct npppd_who` objects for all populated entries, including padding and any untouched bytes. A raw control client receiving the `IMSG_PPP_START` payload can therefore observe leaked daemon stack bytes.

## Why This Is A Real Bug

The serialized data source is a stack buffer. The serialized length includes entire `struct npppd_who` entries. The initializer did not fully initialize those entries before serialization. `strlcpy()` only guarantees NUL termination of the copied string; it does not clear the remaining destination array. The partial `tunnel_peer` initialization similarly left bytes outside the copied sockaddr length unchanged. These bytes are transmitted to the requesting control client, creating a concrete information disclosure.

## Fix Requirement

Fully initialize each `struct npppd_who` before any fields are populated and before the structure is serialized into an imsg payload.

## Patch Rationale

The patch adds:

```c
memset(_this, 0, sizeof(*_this));
```

at the start of `npppd_who_init()`.

This makes every byte of each `struct npppd_who` deterministic before field population. It clears structure padding, unused fixed-size string tails, union tail bytes, and any fields not written on a particular control-flow path. Because all existing assignments occur after the zeroing, intended field values are preserved.

This also fixes both paths that rely on `npppd_who_init()`:

- Active PPP status entries sent as `IMSG_PPP_START`.
- Stopped PPP status snapshots stored in `struct stopped_ppp`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/npppd_ctl.c b/usr.sbin/npppd/npppd/npppd_ctl.c
index e67e568..53e0f2c 100644
--- a/usr.sbin/npppd/npppd/npppd_ctl.c
+++ b/usr.sbin/npppd/npppd/npppd_ctl.c
@@ -268,6 +268,7 @@ npppd_who_init(struct npppd_who *_this, npppd_ppp *ppp)
 	npppd_auth_base *realm = ppp->realm;
 	npppd_iface     *iface = ppp_iface(ppp);
 
+	memset(_this, 0, sizeof(*_this));
 	strlcpy(_this->username, ppp->username, sizeof(_this->username));
 	_this->time = ppp->start_time;
 	clock_gettime(CLOCK_MONOTONIC, &curr_time);
```