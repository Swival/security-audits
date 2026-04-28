# Not Locktokens Satisfy Lock Validation

## Classification

Authorization flaw, high severity.

## Affected Locations

`modules/dav/main/util.c:866`

## Summary

`dav_find_submitted_locktoken()` treated any opaquelock state in an `If` header as a submitted lock token, including tokens wrapped in `Not`. For locked resources, this allowed a modifying request with a non-applicable tagged `If` list containing `Not <locktoken>` to satisfy the required submitted-token check.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Target resource is locked.
- Request is a modifying WebDAV operation, such as `PUT`, `PROPPATCH`, or `DELETE`.
- Request includes an `If` header with a tagged list whose URI does not match the target resource.
- That nonmatching tagged list contains the target resource lock token only as `Not <locktoken>`.

## Proof

`dav_process_if_header()` parses `Not <locktoken>` into a `dav_if_opaquelock` state with `condition == DAV_IF_COND_NOT`.

During locked resource validation, `dav_validate_resource_state()` requires a submitted lock token for modifying requests. If no tagged state applies to the target URI, it calls `dav_find_submitted_locktoken()` to scan the full parsed `If` header.

Before the patch, `dav_find_submitted_locktoken()` matched every `dav_if_opaquelock` state against the resource locks without checking `state_list->condition`. Because the DAV lock providers compare equal lock tokens with a zero return value, the code path:

```c
if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
    return 1;
}
```

returned success even when the only matching token appeared under `Not`.

Result: validation succeeded instead of returning `423 Locked`.

## Why This Is A Real Bug

A `Not <locktoken>` assertion means the client predicates the request on that lock token not being present. It is not a positive submission of the lock token.

Counting `Not` tokens as submitted tokens violates the lock validation requirement and can bypass the normal positive-token path where `auth_user` ownership is checked while evaluating a matching lock-token state.

## Fix Requirement

Only positive opaquelock states may satisfy the submitted-lock-token requirement.

`dav_find_submitted_locktoken()` must ignore `DAV_IF_COND_NOT` states and count only states where:

```c
state_list->condition == DAV_IF_COND_NORMAL
```

## Patch Rationale

The patch narrows `dav_find_submitted_locktoken()` to the same semantic meaning used elsewhere for lock-token submission: a normal, positive opaquelock state.

This preserves valid behavior for legitimate `If` headers while preventing negated lock tokens from satisfying authorization-sensitive lock validation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/main/util.c b/modules/dav/main/util.c
index 50af183..5836ea4 100644
--- a/modules/dav/main/util.c
+++ b/modules/dav/main/util.c
@@ -862,7 +862,8 @@ static int dav_find_submitted_locktoken(const dav_if_header *if_header,
              state_list != NULL;
              state_list = state_list->next) {
 
-            if (state_list->type == dav_if_opaquelock) {
+            if (state_list->condition == DAV_IF_COND_NORMAL
+                && state_list->type == dav_if_opaquelock) {
                 const dav_lock *lock;
 
                 /* given state_list->locktoken, match it */
```