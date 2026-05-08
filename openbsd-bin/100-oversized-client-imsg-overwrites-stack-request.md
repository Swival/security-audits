# Oversized Client imsg Overwrites Stack Request

## Classification

Memory corruption; high severity; stack overwrite in privileged parent-side imsg handling.

## Affected Locations

`usr.sbin/ypldap/ypldap.c:318`

Primary vulnerable copy sites:

`usr.sbin/ypldap/ypldap.c:395`

`usr.sbin/ypldap/ypldap.c:421`

## Summary

`main_dispatch_client()` receives imsgs from the ldapclient child over `env->sc_iev->ibuf`. For `IMSG_PW_ENTRY` and `IMSG_GRP_ENTRY`, it copies the received payload into a fixed stack `struct idm_req ir` using `memcpy()` with length `n - IMSG_HEADER_SIZE`.

The code did not verify that the payload length equals `sizeof(struct idm_req)`. A malicious or compromised ldapclient child that can write arbitrary imsgs to `pipe_main2client` can send a payload larger than `struct idm_req` but still within the imsg layer maximum, causing a stack overwrite in the ypldap parent before `ir.ir_line` is consumed.

## Provenance

Reported and reproduced via Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can write arbitrary imsgs on the `pipe_main2client` socket.

Concrete attacker model: malicious or compromised ldapclient child process.

## Proof

The ldapclient child receives the writable end of `pipe_main2client` in `usr.sbin/ypldap/ldapclient.c:396`, so a malicious child can send arbitrary imsg payloads to the parent.

`struct idm_req` is bounded: it contains a key plus `ir_line[LINE_WIDTH]`, where `LINE_WIDTH` is 1024, defined in `usr.sbin/ypldap/ypldap.h:135` and `usr.sbin/ypldap/ypldap.h:140`.

The imsg layer permits messages up to `MAX_IMSGSIZE` 16384 from `lib/libutil/imsg.h:32`; `lib/libutil/imsg.c:444` rejects only total imsg lengths below the header or above that maximum.

In `main_dispatch_client()`, both entry handlers copy the full imsg payload into the fixed stack object without an upper-bound check:

- `IMSG_PW_ENTRY`: `memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE)` at `usr.sbin/ypldap/ypldap.c:395`
- `IMSG_GRP_ENTRY`: `memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE)` at `usr.sbin/ypldap/ypldap.c:421`

A malicious child can send `IMSG_START_UPDATE` to enter the update path, then send an `IMSG_PW_ENTRY` or `IMSG_GRP_ENTRY` with payload length greater than `sizeof(struct idm_req)` and less than `MAX_IMSGSIZE`. The parent copies that oversized payload past `ir` on the stack before using `ir.ir_line`.

Reproduction status: reproduced.

## Why This Is A Real Bug

The vulnerable destination is a fixed-size stack object and the copy length is attacker-controlled through the imsg payload size. The imsg framing layer validates only generic imsg bounds, not the application-level structure size expected by `IMSG_PW_ENTRY` and `IMSG_GRP_ENTRY`.

Because valid imsgs may be much larger than `struct idm_req`, the existing checks are insufficient. The overwrite happens before semantic parsing of `ir.ir_line`, so corruption occurs even if later processing would reject malformed entry content.

Both vulnerable message types are reachable in the event dispatch loop after `IMSG_START_UPDATE`.

## Fix Requirement

Reject `IMSG_PW_ENTRY` and `IMSG_GRP_ENTRY` payloads whose length is not exactly `sizeof(struct idm_req)` before copying into the stack `struct idm_req`.

## Patch Rationale

The patch adds an exact-size validation immediately before each `memcpy()` into `ir`.

This is the narrowest correct fix because these message types are expected to carry exactly one serialized `struct idm_req`. Accepting shorter messages would leave parts of `ir` uninitialized, and accepting longer messages would preserve the stack overwrite. Failing closed with `fatalx()` prevents continued operation after malformed child-to-parent protocol traffic.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypldap/ypldap.c b/usr.sbin/ypldap/ypldap.c
index ccabd97..d8dca8c 100644
--- a/usr.sbin/ypldap/ypldap.c
+++ b/usr.sbin/ypldap/ypldap.c
@@ -392,6 +392,8 @@ main_dispatch_client(int fd, short events, void *p)
 			if (env->update_trashed)
 				break;
 
+			if (n - IMSG_HEADER_SIZE != sizeof(ir))
+				fatalx("main_dispatch_client: invalid idm_req size");
 			(void)memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE);
 			if ((ue = calloc(1, sizeof(*ue))) == NULL ||
 			    (ue->ue_line = strdup(ir.ir_line)) == NULL) {
@@ -418,6 +420,8 @@ main_dispatch_client(int fd, short events, void *p)
 			if (env->update_trashed)
 				break;
 
+			if (n - IMSG_HEADER_SIZE != sizeof(ir))
+				fatalx("main_dispatch_client: invalid idm_req size");
 			(void)memcpy(&ir, imsg.data, n - IMSG_HEADER_SIZE);
 			if ((ge = calloc(1, sizeof(*ge))) == NULL ||
 			    (ge->ge_line = strdup(ir.ir_line)) == NULL) {
```