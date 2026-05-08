# Missing Challenge Error Object Dereferences NULL

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/acme-client/json.c:401`

## Summary

`json_parse_challenge()` assumes that an invalid ACME challenge response contains an `error` object. An attacker-controlled ACME server can return an `http-01` challenge with `status: "invalid"` and no `error` object. This makes `json_getobj(obj, "error")` return `NULL`, which is then passed to `json_getstr(error, "detail")`. `json_getstr()` dereferences `n->type` immediately, causing a NULL pointer dereference and terminating `acme-client`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client parses an attacker-controlled ACME challenge response.
- The response contains a selected `http-01` challenge.
- The challenge status is absent, invalid, or explicitly maps to `CHNG_INVALID`.
- The challenge omits the `error` object.

## Proof

Relevant control flow:

- `json_parse_challenge()` selects the attacker-supplied `http-01` challenge.
- It copies `url` and `token`.
- It calls `json_parse_response(obj)` at `usr.sbin/acme-client/json.c:399`.
- If `status` maps to `CHNG_INVALID`, execution enters the invalid-status branch.
- `json_getobj(obj, "error")` can return `NULL` when the object is missing.
- `json_getstr(error, "detail")` is then called with `error == NULL`.
- `json_getstr()` immediately reads `n->type` at `usr.sbin/acme-client/json.c:284`, causing a NULL dereference.

Example triggering response shape:

```json
{
  "challenges": [
    {
      "type": "http-01",
      "url": "https://attacker.example/chal",
      "token": "tok",
      "status": "invalid"
    }
  ]
}
```

Impact: `acme-client` terminates before completing certificate issuance.

## Why This Is A Real Bug

The missing `error` object is reachable through normal JSON parsing of a remote ACME challenge response. The code already treats malformed or unexpected statuses as `CHNG_INVALID`, but the invalid-status handling path assumes optional error metadata is present. Because `json_getstr()` does not accept `NULL`, this is a direct, deterministic NULL pointer dereference on attacker-controlled input.

## Fix Requirement

Check that `json_getobj(obj, "error")` returned a non-NULL object before calling `json_getstr(error, "detail")`.

## Patch Rationale

The patch preserves existing behavior when an `error` object is present and safely skips detail extraction when it is absent. The challenge remains invalid via `p->status == CHNG_INVALID`; only the optional diagnostic string is omitted. This removes the crash without changing challenge selection or status parsing semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/acme-client/json.c b/usr.sbin/acme-client/json.c
index 4081269..297256b 100644
--- a/usr.sbin/acme-client/json.c
+++ b/usr.sbin/acme-client/json.c
@@ -401,7 +401,8 @@ json_parse_challenge(struct jsmnn *n, struct chng *p)
 		p->status = json_parse_response(obj);
 		if (p->status == CHNG_INVALID) {
 			error = json_getobj(obj, "error");
-			p->error = json_getstr(error, "detail");
+			if (error != NULL)
+				p->error = json_getstr(error, "detail");
 		}
 		return p->uri != NULL && p->token != NULL;
 	}
```