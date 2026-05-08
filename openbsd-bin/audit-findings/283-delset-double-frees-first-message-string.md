# delset double-frees first message string

## Classification

Memory corruption, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/gencat/gencat.c:686`

## Summary

`MCDelSet()` deletes messages from a set without advancing the message iterator. A crafted msgfile containing a `$delset` directive for a set with at least one message causes the loop to process the same removed message node again, double-freeing `msg->str` and repeating `LIST_REMOVE()` on an already-removed list entry.

## Provenance

Verified from the supplied source, reproduced with the supplied msgfile pattern, and reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim runs `gencat` on an attacker-controlled msgfile.

## Proof

A minimal triggering msgfile is:

```text
$set 1
1 hello
$delset 1
```

Reachability is direct:

- `main()` opens each msgfile and calls `MCParse()` at `usr.bin/gencat/gencat.c:159`.
- `MCParse()` parses attacker-controlled `$delset` lines and dispatches to `MCDelSet(setid)` at `usr.bin/gencat/gencat.c:421`.
- `MCDelSet()` initializes `msg = LIST_FIRST(&set->msghead)` at `usr.bin/gencat/gencat.c:687`.
- The loop condition `while (msg)` remains true because `msg` is never reassigned.
- The first iteration frees `msg->str` and removes `msg` from the list.
- The second iteration reaches `free(msg->str)` again at `usr.bin/gencat/gencat.c:689` and repeats `LIST_REMOVE(msg, entries)` at `usr.bin/gencat/gencat.c:690`.

## Why This Is A Real Bug

The attacker-controlled `$delset` directive reaches the vulnerable code path without special privileges. When the target set contains at least one message, `msg` continues to point to the same removed node after `LIST_REMOVE()`. The next loop iteration frees the same string pointer again and corrupts list metadata by removing the same entry twice. This is attacker-triggered memory corruption in the `gencat` process and can cause a crash or denial of service.

## Fix Requirement

Before removing a message node, save its successor with `LIST_NEXT(msg, entries)`. After freeing and removing the current node, advance `msg` to the saved successor so each message is processed exactly once.

## Patch Rationale

The patch captures `nextmsg` before `LIST_REMOVE()` mutates the list links. It then frees the current message string, removes the current message node from the set list, and advances to `nextmsg`. This preserves valid traversal state and prevents revisiting the same removed node.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/gencat/gencat.c b/usr.bin/gencat/gencat.c
index bb66db1..253a225 100644
--- a/usr.bin/gencat/gencat.c
+++ b/usr.bin/gencat/gencat.c
@@ -686,8 +686,11 @@ MCDelSet(int setId)
 
 		msg = LIST_FIRST(&set->msghead);
 		while (msg) {
+			struct _msgT *nextmsg = LIST_NEXT(msg, entries);
+
 			free(msg->str);
 			LIST_REMOVE(msg, entries);
+			msg = nextmsg;
 		}
 
 		LIST_REMOVE(set, entries);
```