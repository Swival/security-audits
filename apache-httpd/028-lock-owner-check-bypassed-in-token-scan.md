# Lock Owner Check Bypassed In Token Scan

## Classification

Authorization flaw, high severity. Confidence: certain.

## Affected Locations

`modules/dav/main/util.c:883`

## Summary

`dav_validate_resource_state()` enforces `lock->auth_user` when a lock token is matched in the normal per-state validation path, but its fallback token scan used `dav_find_submitted_locktoken()`, which accepted matching lock tokens without checking ownership. A different authenticated user could submit another user's valid lock token in a non-applicable or otherwise separately scanned `If` header list and satisfy locked-resource validation.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Resource is locked.
- Request includes a valid lock token in the `If` header.
- Caller differs from `lock->auth_user`.
- Validation reaches the fallback token scan in `dav_find_submitted_locktoken()`.

## Proof

`dav_process_if_header()` parses the request `If` header into `if_header`.

During normal per-state lock matching in `dav_validate_resource_state()`, the code correctly enforces the lock owner invariant:

```c
if (lock->auth_user &&
    (!r->user ||
     strcmp(lock->auth_user, r->user))) {
    ...
    return dav_new_error(p, HTTP_FORBIDDEN, 0, 0, errmsg);
}
```

However, when an applicable state list matches without setting `seen_locktoken`, validation falls back to scanning all submitted tokens:

```c
if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks)) {
    return NULL;
}
```

Before the patch, `dav_find_submitted_locktoken()` only compared token values:

```c
if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
    return 1;
}
```

A practical trigger is a modifying request by `bob` against Alice's locked `/locked`, where Alice's lock token `T` appears only in a non-applicable tagged list:

```http
PUT /locked HTTP/1.1
If: <http://host/locked> (Not <opaquelocktoken:00000000-0000-0000-0000-000000000000>) <http://host/other> (<opaquelocktoken:T>)
```

The `/locked` tagged list applies and succeeds via the harmless non-matching `Not` token without setting `seen_locktoken`. The fallback helper then scans all `If` header lists, finds Alice's token `T` under `/other`, returns success, and validation returns `NULL`, allowing the modifying method despite `bob != lock->auth_user`.

## Why This Is A Real Bug

The normal validation path documents and enforces the invariant that if an authenticated user created a lock, only that same user may submit the lock token to manipulate the resource. The fallback helper is part of the same locked-resource validation flow but skipped the same authorization check. Because that helper can independently satisfy the “submitted lock token” requirement, the omission creates an authorization bypass rather than a cosmetic inconsistency.

## Fix Requirement

`dav_find_submitted_locktoken()` must validate `lock->auth_user` before accepting a matching submitted lock token. A token should satisfy the fallback scan only when the lock is unauthenticated or the current request user matches the lock owner.

## Patch Rationale

The patch extends `dav_find_submitted_locktoken()` to receive the authenticated request user and requires ownership compatibility alongside token equality:

```c
if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)
    && (!lock->auth_user
        || (auth_user && !strcmp(lock->auth_user, auth_user)))) {
    return 1;
}
```

Both fallback callers in `dav_validate_resource_state()` now pass `r->user`, aligning fallback token acceptance with the existing normal-path authorization rule. This preserves unauthenticated-lock behavior while rejecting tokens owned by a different authenticated user.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/main/util.c b/modules/dav/main/util.c
index 50af183..6eaa9e7 100644
--- a/modules/dav/main/util.c
+++ b/modules/dav/main/util.c
@@ -853,7 +853,8 @@ static dav_error * dav_process_if_header(request_rec *r, dav_if_header **p_ih)
 
 static int dav_find_submitted_locktoken(const dav_if_header *if_header,
                                         const dav_lock *lock_list,
-                                        const dav_hooks_locks *locks_hooks)
+                                        const dav_hooks_locks *locks_hooks,
+                                        const char *auth_user)
 {
     for (; if_header != NULL; if_header = if_header->next) {
         const dav_if_state_list *state_list;
@@ -882,7 +883,9 @@ static int dav_find_submitted_locktoken(const dav_if_header *if_header,
                 */
                 for (lock = lock_list; lock != NULL; lock = lock->next) {
 
-                    if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
+                    if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)
+                        && (!lock->auth_user
+                            || (auth_user && !strcmp(lock->auth_user, auth_user)))) {
                         return 1;
                     }
                 }
@@ -1383,7 +1386,7 @@ static dav_error * dav_validate_resource_state(apr_pool_t *p,
             ** which implies locks_hooks != NULL.
             */
             if (dav_find_submitted_locktoken(if_header, lock_list,
-                                             locks_hooks)) {
+                                             locks_hooks, r->user)) {
                 /*
                 ** We found a match! We're set... none of the If: header
                 ** assertions apply (implicit success), and the If: header
@@ -1442,7 +1445,7 @@ static dav_error * dav_validate_resource_state(apr_pool_t *p,
     ** Note that seen_locktoken == 0 implies lock_list != NULL which implies
     ** locks_hooks != NULL.
     */
-    if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks)) {
+    if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks, r->user)) {
         /*
         ** We found a match! We're set... we have a matching state list,
         ** and the If: header specified the locktoken somewhere. We're done.
```