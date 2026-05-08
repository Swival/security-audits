# Unauthenticated Dump Request Writes Through Null Response Pointer

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/rpc.bootparamd/bootparamd.c:235`

## Summary

An unauthenticated remote RPC `getfile` request with `file_id == "dump"` can terminate `rpc.bootparamd` when the resolved client is configured in bootparams but lacks a `dump` parameter.

The vulnerable fallback path attempts to write NUL bytes through `res.server_name` and `res.server_path`. On the first matching request, those static response pointers are still zero-initialized, so the writes dereference null pointers.

## Provenance

Reported and reproduced from Swival Security Scanner output.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The attacker can send unauthenticated RPC requests to `rpc.bootparamd`.
- `getfile->client_name` resolves through `gethostbyname`.
- The resolved client has a matching bootparams entry.
- That entry lacks the requested `dump` parameter.
- No prior successful `getfile` request has initialized `res.server_name` and `res.server_path`.

## Proof

`bootparamproc_getfile_1_svc` accepts attacker-controlled `getfile->client_name` and `getfile->file_id`.

For a resolving configured client:

- `usr.sbin/rpc.bootparamd/bootparamd.c:225` calls `lookup_bootparam(askname, NULL, getfile->file_id, &res.server_name, &res.server_path)`.
- `usr.sbin/rpc.bootparamd/bootparamd.c:342` records that a matching client entry was found.
- `usr.sbin/rpc.bootparamd/bootparamd.c:346` returns `ENOENT` when that entry does not contain the requested parameter.
- With `file_id == "dump"`, `usr.sbin/rpc.bootparamd/bootparamd.c:233` enters the special dump fallback.
- `usr.sbin/rpc.bootparamd/bootparamd.c:235` writes `res.server_name[0] = '\0'`.
- `usr.sbin/rpc.bootparamd/bootparamd.c:236` writes `res.server_path[0] = '\0'`.

Because `res` is a static `bp_getfile_res`, its pointer fields are initially null. On the first such dump fallback, both writes target address zero, terminating the daemon.

## Why This Is A Real Bug

The crash is reachable through normal RPC service flow without authentication. The lookup result `ENOENT` is not a fatal error for `file_id == "dump"`; instead, the code deliberately returns empty strings. However, it attempts to create those empty strings by writing through response pointers that may not point to allocated storage.

This is not only a theoretical null dereference: the vulnerable writes happen after successful client resolution and matching bootparams lookup, and the required missing `dump` field is a valid configuration state.

## Fix Requirement

The dump fallback must return valid empty strings without writing through uninitialized response pointers.

Acceptable fixes include:

- Assigning `res.server_name` and `res.server_path` to static empty strings.
- Providing fixed backing buffers before writing into them.

## Patch Rationale

The patch replaces writes through possibly null pointers with assignments to string literals:

```c
res.server_name = "";
res.server_path = "";
```

This preserves the intended protocol behavior for missing `dump` parameters: return empty server and path strings. It also avoids depending on prior successful requests to initialize the static response object.

The server address is still zeroed as before.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpc.bootparamd/bootparamd.c b/usr.sbin/rpc.bootparamd/bootparamd.c
index cead376..e12c1bd 100644
--- a/usr.sbin/rpc.bootparamd/bootparamd.c
+++ b/usr.sbin/rpc.bootparamd/bootparamd.c
@@ -232,8 +232,8 @@ bootparamproc_getfile_1_svc(bp_getfile_arg *getfile, struct svc_req *rqstp)
 		res.server_address.address_type = IP_ADDR_TYPE;
 	} else if (error == ENOENT && !strcmp(getfile->file_id, "dump")) {
 		/* Special for dump, answer with null strings. */
-		res.server_name[0] = '\0';
-		res.server_path[0] = '\0';
+		res.server_name = "";
+		res.server_path = "";
 		bzero(&res.server_address.bp_address_u.ip_addr, 4);
 	} else {
 failed:
```