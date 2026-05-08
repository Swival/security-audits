# Revoked LDP MD5 Auth Entries Survive Reload

## Classification

Authentication bypass; high severity; confidence certain.

## Affected Locations

`usr.sbin/ldpd/ldpd.c:857`

`usr.sbin/ldpd/ldpd.c:1259`

## Summary

Reloading `ldpd` configuration after deleting an LDP MD5 authentication entry does not remove the old entry from the active configuration. A peer that knows the revoked MD5 key can still authenticate after reload because the stale credential remains in `conf->auth_list` and is later used for TCP MD5 SA installation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An administrator reloads configuration after deleting an existing LDP MD5 authentication entry.

## Proof

`ldp_reload()` parses the replacement configuration, sends it to child processes, and then calls `merge_config()` on the active configuration.

`merge_config()` calls `merge_auths()`. In the deleted-auth loop, `merge_auths()` checks each old `auth` entry against the new config with `auth_find(xconf, auth)`. The buggy condition continues when `auth_find()` returns `NULL`, so entries absent from the new config are not removed.

The stale auth list is security-active. `pfkey_find_auth()` scans `conf->auth_list`; `pfkey_establish()` selects an auth entry; and `pfkey_md5sig_establish()` installs TCP MD5 SAs using `auth->md5key`.

A practical bypass exists after reload removes a configured MD5 entry. A malicious LDP peer that knows the removed key can initiate or renew a session. If the old config contained a more-specific key and the new config deletes it while leaving a broader or different MD5 policy, the stale more-specific entry remains and wins via longest-prefix selection in `pfkey_find_auth()`. New neighbors reach this path through `nbr_new -> pfkey_establish`.

## Why This Is A Real Bug

The implementation reverses the intended deleted-entry test. Deleted entries are exactly those for which `auth_find(xconf, auth)` returns `NULL`, but the code skips those entries and removes entries that still exist in the new configuration. Because MD5 authentication material directly controls peer session authentication, retaining a removed key allows authentication with a credential the administrator explicitly revoked.

## Fix Requirement

Remove old authentication entries when `auth_find(xconf, auth)` returns `NULL`.

## Patch Rationale

The patch changes the deleted-auth loop to continue only when a matching auth entry still exists in the new configuration. Therefore, absent entries fall through to `LIST_REMOVE(auth, entry)` and `free(auth)`, correctly deleting revoked MD5 credentials from the active list during reload.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldpd/ldpd.c b/usr.sbin/ldpd/ldpd.c
index 4032c02..49b143f 100644
--- a/usr.sbin/ldpd/ldpd.c
+++ b/usr.sbin/ldpd/ldpd.c
@@ -1259,7 +1259,7 @@ merge_auths(struct ldpd_conf *conf, struct ldpd_conf *xconf)
 	/* find deleted auths */
 	LIST_FOREACH_SAFE(auth, &conf->auth_list, entry, nauth) {
 		xauth = auth_find(xconf, auth);
-		if (xauth == NULL)
+		if (xauth != NULL)
 			continue;
 
 		LIST_REMOVE(auth, entry);
```