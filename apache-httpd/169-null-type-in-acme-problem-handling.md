# Null ACME Problem Type Dereference

## Classification

Validation gap; medium severity.

## Affected Locations

`modules/md/md_acme.c:187`

## Summary

`inspect_problem()` trusts the `type` member of an ACME `application/problem+json` response. If the ACME server returns a problem document without a string `type`, `md_json_gets()` returns `NULL`, and the value is passed into `problem_status_get()`, which immediately dereferences it through `strstr()`. A server-controlled non-2xx ACME response can therefore crash the client path with a NULL pointer dereference.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- ACME server returns a non-2xx HTTP response.
- Response content type is exactly `application/problem+json` after parsing.
- Response body parses successfully as JSON.
- The JSON body omits `type`, or `type` exists but is not a JSON string.

## Proof

`on_response()` routes all non-2xx ACME responses to `inspect_problem(req, res)` at `modules/md/md_acme.c:320`.

Inside `inspect_problem()`, the code accepts `application/problem+json`, parses the response body with `md_json_read_http()`, then reads:

```c
ptype = md_json_gets(problem, MD_KEY_TYPE, NULL);
```

at `modules/md/md_acme.c:184`.

`md_json_gets()` returns `NULL` when the selected JSON value is absent or not a string, as confirmed at `modules/md/md_json.c:406`.

Before the patch, `inspect_problem()` then passed `ptype` directly into:

```c
req->rv = problem_status_get(ptype);
```

at `modules/md/md_acme.c:186`.

`problem_status_get()` immediately evaluates:

```c
if (strstr(type, "urn:ietf:params:") == type) {
```

at `modules/md/md_acme.c:76`.

If `type` is `NULL`, this is a reachable NULL dereference. Minimal crashing bodies include `{}` and `{"detail":"x"}`.

## Why This Is A Real Bug

The failing value is controlled by the ACME server response body. RFC 7807 problem documents normally include `type`, but the client must not assume the field is present or has the expected type when parsing an error response. The code already has generic fallback handling for unknown HTTP failures, but this path crashes before it can use that fallback.

The crash also applies when `type` is present but not a string, because `md_json_gets()` still returns `NULL`.

## Fix Requirement

Before calling `problem_status_get()`, validate that `ptype` is non-NULL. If no usable problem type is available, classify the ACME problem as a generic error using `APR_EGENERAL`.

## Patch Rationale

The patch changes only the status mapping decision:

```c
req->rv = ptype? problem_status_get(ptype) : APR_EGENERAL;
```

This preserves existing behavior for valid ACME problem types, avoids passing `NULL` into `problem_status_get()`, and keeps malformed or incomplete problem documents on the existing generic-error path.

`md_result_problem_set()` still receives the original `ptype`, including `NULL`, so result reporting remains faithful to the parsed response while avoiding the crash.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_acme.c b/modules/md/md_acme.c
index 099d3a4..50e09ab 100644
--- a/modules/md/md_acme.c
+++ b/modules/md/md_acme.c
@@ -183,7 +183,7 @@ static apr_status_t inspect_problem(md_acme_req_t *req, const md_http_response_t
             req->resp_json = problem;
             ptype = md_json_gets(problem, MD_KEY_TYPE, NULL); 
             pdetail = md_json_gets(problem, MD_KEY_DETAIL, NULL);
-            req->rv = problem_status_get(ptype);
+            req->rv = ptype? problem_status_get(ptype) : APR_EGENERAL;
             md_result_problem_set(req->result, req->rv, ptype, pdetail,
                                   md_json_getj(problem, MD_KEY_SUBPROBLEMS, NULL));
```