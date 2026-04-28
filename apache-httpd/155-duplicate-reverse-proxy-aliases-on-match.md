# Duplicate Reverse Proxy Aliases On Match

## Classification

Logic error, medium severity.

## Affected Locations

`modules/proxy/mod_proxy_express.c:214`

## Summary

`mod_proxy_express` incorrectly adds a duplicate reverse proxy alias when an existing alias already matches the backend returned from the DBM lookup. The loop detects the existing alias, but clears `ralias` to `NULL`; the later `if (!ralias)` check interprets that matched state as "not found" and appends another alias.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ProxyExpress` is enabled.
- The request reaches `xlate_name`.
- The DBM lookup for the request server name returns a backend.
- `dconf->raliases` already contains a reverse proxy alias whose `real` value matches that backend case-insensitively.

## Proof

The reproduced flow is:

- `backend` is populated from `apr_dbm_fetch`.
- `backend` is used to rewrite the request as a reverse proxy request.
- `backend` is compared against each existing `ralias->real` with `strcasecmp`.
- On a match, the loop enters the match branch and sets `ralias = NULL`.
- The loop exits.
- The following `if (!ralias)` branch treats the match as absence and appends a new alias with `apr_array_push`.

This contradicts the nearby invariant comment: "If so, don't do it again."

The duplicate entry is reachable on any translated request whose server-name DBM entry maps to an already-present backend.

## Why This Is A Real Bug

A matched existing alias should suppress insertion. Instead, the matched state is encoded as `NULL`, which is the same condition used by the insertion branch. As a result, every matching request can append another duplicate `ProxyPassReverse` alias to the process-local `dconf->raliases` array.

This causes persistent per-process config-pool growth and increases work for reverse header rewriting, which iterates `conf->raliases` in `modules/proxy/proxy_util.c:907`.

## Fix Requirement

The code must distinguish "found existing alias" from "completed the loop without finding one." A new alias should be added only when the loop examines all existing entries without a match.

## Patch Rationale

The patch removes the incorrect `ralias = NULL` assignment on match and changes the insertion condition to `i >= dconf->raliases->nelts`.

This makes the loop index the source of truth:

- If a match occurs, `break` exits with `i < dconf->raliases->nelts`, so no duplicate is added.
- If no match occurs, the loop completes with `i >= dconf->raliases->nelts`, so a new alias is added.

The change preserves the existing matching behavior and only corrects the found/not-found decision.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_express.c b/modules/proxy/mod_proxy_express.c
index 5d458c4..411e420 100644
--- a/modules/proxy/mod_proxy_express.c
+++ b/modules/proxy/mod_proxy_express.c
@@ -203,13 +203,12 @@ static int xlate_name(request_rec *r)
      */
     for (i = 0; i < dconf->raliases->nelts; i++, ralias++) {
         if (strcasecmp(backend, ralias->real) == 0) {
-            ralias = NULL;
             break;
         }
     }
 
     /* Didn't find one... add it */
-    if (!ralias) {
+    if (i >= dconf->raliases->nelts) {
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01006)
                       "proxy_express: adding PPR entry");
         ralias = apr_array_push(dconf->raliases);
```