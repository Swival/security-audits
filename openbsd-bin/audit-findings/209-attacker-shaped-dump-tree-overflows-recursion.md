# Attacker-Shaped Dump Tree Overflows Recursion

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

- `usr.bin/showmount/showmount.c:237`
- `usr.bin/showmount/showmount.c:260`
- `usr.bin/showmount/showmount.c:360`
- `usr.bin/showmount/showmount.c:367`
- `usr.bin/showmount/showmount.c:394`

## Summary

`showmount` decodes attacker-controlled `RPCMNT_DUMP` entries into an unbalanced binary tree, then recursively traverses that tree in `print_dump()`. A malicious mount daemon can return lexicographically ordered unique entries that force the tree into a deep chain. Traversal then consumes one stack frame per node and can exhaust the client process stack, aborting `showmount`.

The patch replaces recursive inorder traversal with an explicit heap-allocated stack, preserving sorted output while removing attacker-controlled call-stack growth.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and confirmed against `usr.bin/showmount/showmount.c`.

## Preconditions

- User queries an attacker-controlled host.
- `DODUMP` is enabled, either by default or through `-a` / `-d`.
- The attacker-controlled host runs or emulates a malicious RPC mount daemon.
- The malicious daemon returns many sorted, unique `RPCMNT_DUMP` entries.

## Proof

`main()` calls:

```c
clnt_call(client, RPCMNT_DUMP, xdr_void, NULL,
    xdr_mntdump, (char *)&mntdump, timeout);
```

The queried host controls the decoded mount dump list.

`xdr_mntdump()` allocates one `struct mountlist` per returned entry and inserts each unique entry into an unbalanced binary tree. Ordering is controlled by `strcmp()` on attacker-provided host and directory strings. There is no total-entry limit and no tree-depth limit.

Sorted unique entries therefore create a degenerate tree:

- Ascending unique keys force repeated right-child insertion.
- Descending unique keys force repeated left-child insertion.
- In both cases, the resulting tree depth is proportional to the number of entries.

`print_dump()` then performs recursive inorder traversal:

```c
if (mp->ml_left)
    print_dump(mp->ml_left);
...
if (mp->ml_right)
    print_dump(mp->ml_right);
```

Each recursive frame also contains fixed stack arrays:

```c
char vn[(RPCMNT_NAMELEN+1)*4];
char vp[(RPCMNT_PATHLEN+1)*4];
```

A sufficiently long attacker-shaped dump list exhausts the process stack before memory exhaustion is required.

The issue was reproduced with a same-shape harness using mount protocol string limits; a few thousand short unique entries were enough to trigger stack exhaustion.

## Why This Is A Real Bug

The vulnerable data structure is fully influenced by the remote mount daemon queried by the user. The client trusts the decoded dump list enough to allocate entries, order them, and recursively traverse them without bounding depth.

The crash does not depend on malformed XDR or invalid memory. The attacker can use valid `RPCMNT_DUMP` responses containing sorted unique host/path strings. Because the tree is unbalanced, valid input shape alone determines recursion depth.

The impact is denial of service of the local `showmount` process.

## Fix Requirement

The traversal must not consume process call stack in proportion to attacker-controlled tree depth.

Acceptable fixes include:

- Replacing recursive traversal with iterative traversal using an explicit stack.
- Balancing the tree during insertion so traversal depth remains bounded logarithmically.
- Enforcing a safe total-entry or tree-depth limit before traversal.

## Patch Rationale

The patch implements iterative inorder traversal in `print_dump()`.

It preserves existing behavior:

- Output remains sorted by the existing binary tree ordering.
- `ALL`, `DIRS`, and default output modes are unchanged.
- `strvis()` formatting and printed fields are unchanged.

It removes the vulnerability:

- Tree depth no longer maps to recursive call depth.
- The explicit traversal stack is heap allocated with `reallocarray()`.
- Stack capacity growth is checked for overflow.
- Allocation failure terminates safely with `err()`.

The fix is narrow and localized to printing, avoiding changes to XDR decoding or insertion semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/showmount/showmount.c b/usr.bin/showmount/showmount.c
index c264f68..000dad7 100644
--- a/usr.bin/showmount/showmount.c
+++ b/usr.bin/showmount/showmount.c
@@ -359,28 +359,46 @@ usage(void)
 void
 print_dump(struct mountlist *mp)
 {
+	struct mountlist **stack, **newstack;
+	size_t stacklen, stacksize, newstacksize;
 	char	vn[(RPCMNT_NAMELEN+1)*4];
 	char	vp[(RPCMNT_PATHLEN+1)*4];
 
-	if (mp == NULL)
-		return;
-	if (mp->ml_left)
-		print_dump(mp->ml_left);
-	switch (type) {
-	case ALL:
-		strvis(vn, mp->ml_host, VIS_CSTYLE);
-		strvis(vp, mp->ml_dirp, VIS_CSTYLE);
-		printf("%s:%s\n", vn, vp);
-		break;
-	case DIRS:
-		strvis(vp, mp->ml_dirp, VIS_CSTYLE);
-		printf("%s\n", vp);
-		break;
-	default:
-		strvis(vn, mp->ml_host, VIS_CSTYLE);
-		printf("%s\n", vn);
-		break;
+	stack = NULL;
+	stacklen = stacksize = 0;
+	while (mp != NULL || stacklen != 0) {
+		while (mp != NULL) {
+			if (stacklen == stacksize) {
+				newstacksize = stacksize == 0 ? 32 : stacksize * 2;
+				if (newstacksize <= stacksize)
+					errx(1, "mount dump too large");
+				newstack = reallocarray(stack, newstacksize,
+				    sizeof(*stack));
+				if (newstack == NULL)
+					err(1, "reallocarray");
+				stack = newstack;
+				stacksize = newstacksize;
+			}
+			stack[stacklen++] = mp;
+			mp = mp->ml_left;
+		}
+		mp = stack[--stacklen];
+		switch (type) {
+		case ALL:
+			strvis(vn, mp->ml_host, VIS_CSTYLE);
+			strvis(vp, mp->ml_dirp, VIS_CSTYLE);
+			printf("%s:%s\n", vn, vp);
+			break;
+		case DIRS:
+			strvis(vp, mp->ml_dirp, VIS_CSTYLE);
+			printf("%s\n", vp);
+			break;
+		default:
+			strvis(vn, mp->ml_host, VIS_CSTYLE);
+			printf("%s\n", vn);
+			break;
+		}
+		mp = mp->ml_right;
 	}
-	if (mp->ml_right)
-		print_dump(mp->ml_right);
+	free(stack);
 }
```