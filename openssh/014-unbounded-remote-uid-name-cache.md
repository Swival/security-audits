# Unbounded Remote UID/GID Name Cache

## Classification

Denial of service, medium severity.

## Affected Locations

`sftp-usergroup.c:114`

## Summary

The SFTP client permanently caches remote UID and GID name resolutions returned by a server. An attacker-controlled SFTP server can supply directory entries with many distinct UID/GID values and resolve each value to a name, causing unbounded client memory growth during remote listings.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The client uses the user/group lookup extension.
- The SFTP server is attacker-controlled or malicious.
- The attacker can cause listings containing many distinct remote UID/GID values.

## Proof

`do_ls_dir()` calls `get_remote_user_groups_from_dirents()` during remote directory listing.

`collect_ids_from_dirents()` collects unseen server-supplied IDs from `SFTP_DIRENT` records:

- `d[i]->a.uid` at `sftp-usergroup.c:193`
- `d[i]->a.gid` at `sftp-usergroup.c:199`

`lookup_and_record()` sends those IDs to `sftp_get_users_groups_by_id()` and records every non-NULL resolved name:

- user lookup handling at `sftp-usergroup.c:108`
- user cache insert at `sftp-usergroup.c:119`
- group cache insert at `sftp-usergroup.c:127`

Before the patch, `idname_enter()` allocated a new permanent RB-tree entry and duplicated name:

- node allocation at `sftp-usergroup.c:68`
- name duplication at `sftp-usergroup.c:71`
- only duplicate IDs were freed at `sftp-usergroup.c:72`

The source comment also explicitly stated the missing bounded cache implementation:

```c
/* XXX implement bounded cache as TAILQ */
```

Per-message limits do not bound this lifetime cache. A malicious server can keep each listing and lookup below `SFTP_MAX_MSG_LENGTH` while returning fresh IDs across listings, growing client memory until allocation failure or OOM termination.

## Why This Is A Real Bug

All growth inputs are remote-controlled: the server supplies directory entry UID/GID values and the corresponding resolved names. The client stores successful resolutions in global RB-tree caches without eviction or a maximum size. The cache persists across listings, so repeated listings with distinct IDs create cumulative memory growth. This is sufficient for denial of service against a client that uses the extension.

## Fix Requirement

The UID and GID name caches must have a hard upper bound and must evict older entries when the bound is exceeded. Eviction must remove entries from all cache indexes and free both the duplicated name and node.

## Patch Rationale

The patch implements the previously noted bounded cache design:

- Adds `IDNAME_CACHE_MAX` with a fixed limit of 1024 entries per cache.
- Adds a `TAILQ` alongside each RB tree to track insertion order.
- Tracks separate user and group cache counts.
- Skips insertion when an ID is already cached.
- Inserts new entries into both the RB tree and FIFO queue.
- Evicts oldest entries while the cache exceeds the limit.
- Removes evicted entries from both the queue and RB tree before freeing them.
- Treats RB-tree/queue inconsistency as fatal cache corruption.

This preserves efficient lookup by ID while bounding lifetime memory use.

## Residual Risk

None

## Patch

```diff
diff --git a/sftp-usergroup.c b/sftp-usergroup.c
index 47cf04a..2c08bbe 100644
--- a/sftp-usergroup.c
+++ b/sftp-usergroup.c
@@ -17,6 +17,7 @@
 /* sftp client user/group lookup and caching */
 
 #include <sys/types.h>
+#include <sys/queue.h>
 #include <sys/tree.h>
 
 #include <glob.h>
@@ -32,11 +33,13 @@
 #include "sftp-usergroup.h"
 
 /* Tree of id, name */
+#define IDNAME_CACHE_MAX	1024
+
 struct idname {
         u_int id;
 	char *name;
         RB_ENTRY(idname) entry;
-	/* XXX implement bounded cache as TAILQ */
+	TAILQ_ENTRY(idname) qentry;
 };
 static int
 idname_cmp(struct idname *a, struct idname *b)
@@ -47,9 +50,15 @@ idname_cmp(struct idname *a, struct idname *b)
 }
 RB_HEAD(idname_tree, idname);
 RB_GENERATE_STATIC(idname_tree, idname, entry, idname_cmp)
+TAILQ_HEAD(idname_queue, idname);
 
 static struct idname_tree user_idname = RB_INITIALIZER(&user_idname);
 static struct idname_tree group_idname = RB_INITIALIZER(&group_idname);
+static struct idname_queue user_idname_queue =
+    TAILQ_HEAD_INITIALIZER(user_idname_queue);
+static struct idname_queue group_idname_queue =
+    TAILQ_HEAD_INITIALIZER(group_idname_queue);
+static size_t user_idname_count, group_idname_count;
 
 static void
 idname_free(struct idname *idname)
@@ -61,16 +70,34 @@ idname_free(struct idname *idname)
 }
 
 static void
-idname_enter(struct idname_tree *tree, u_int id, const char *name)
+idname_enter(struct idname_tree *tree, struct idname_queue *queue,
+    size_t *count, u_int id, const char *name)
 {
-	struct idname *idname;
+	struct idname find, *idname, *old;
 
+	memset(&find, 0, sizeof(find));
+	find.id = id;
+	if (RB_FIND(idname_tree, tree, &find) != NULL)
+		return;
 	if ((idname = xcalloc(1, sizeof(*idname))) == NULL)
 		fatal_f("alloc");
 	idname->id = id;
 	idname->name = xstrdup(name);
-	if (RB_INSERT(idname_tree, tree, idname) != NULL)
+	if (RB_INSERT(idname_tree, tree, idname) != NULL) {
 		idname_free(idname);
+		return;
+	}
+	TAILQ_INSERT_TAIL(queue, idname, qentry);
+	(*count)++;
+	while (*count > IDNAME_CACHE_MAX) {
+		if ((old = TAILQ_FIRST(queue)) == NULL)
+			fatal_f("idname cache corrupt");
+		TAILQ_REMOVE(queue, old, qentry);
+		if (RB_REMOVE(idname_tree, tree, old) != old)
+			fatal_f("idname cache corrupt");
+		idname_free(old);
+		(*count)--;
+	}
 }
 
 static const char *
@@ -116,7 +143,8 @@ lookup_and_record(struct sftp_conn *conn,
 			continue;
 		}
 		debug3_f("record uid %u => \"%s\"", uids[i], usernames[i]);
-		idname_enter(&user_idname, uids[i], usernames[i]);
+		idname_enter(&user_idname, &user_idname_queue,
+		    &user_idname_count, uids[i], usernames[i]);
 	}
 	for (i = 0; i < ngids; i++) {
 		if (groupnames[i] == NULL) {
@@ -124,7 +152,8 @@ lookup_and_record(struct sftp_conn *conn,
 			continue;
 		}
 		debug3_f("record gid %u => \"%s\"", gids[i], groupnames[i]);
-		idname_enter(&group_idname, gids[i], groupnames[i]);
+		idname_enter(&group_idname, &group_idname_queue,
+		    &group_idname_count, gids[i], groupnames[i]);
 	}
 	freenames(usernames, nuids);
 	freenames(groupnames, ngids);
```