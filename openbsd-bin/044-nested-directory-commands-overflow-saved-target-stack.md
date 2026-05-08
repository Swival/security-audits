# Nested Directory Commands Overflow Saved Target Stack

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.bin/rdistd/server.c:1438`

## Summary

`rdistd` stores nested directory target pointers in the global array `sptarget[32]`. The directory receive path checks `catname` against `sizeof(sptarget)`, which is the byte size of the array, not the number of pointer slots. A remote protocol client can send more than 32 nested `C_RECVDIR` commands and cause `sptarget[catname] = ptarget` to write past the end of the 32-element global array.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker completes rdist protocol version negotiation.
- Attacker sends directory receive commands through the server protocol.
- The server dispatches `C_RECVDIR` to `recvit(cp, S_IFDIR)`.

## Proof

The vulnerable check is:

```c
if ((size_t) catname >= sizeof(sptarget)) {
	error("%s: too many directory levels", target);
	return;
}
sptarget[catname] = ptarget;
```

`sptarget` is declared as:

```c
char *sptarget[32];
```

`sizeof(sptarget)` evaluates to the byte size of the array, not the slot count. On typical targets this is 128 bytes on 32-bit or 256 bytes on 64-bit systems. Therefore `catname == 32` passes the guard even though valid indexes are only `0..31`.

Reachability is direct:

- `server()` dispatches `C_RECVDIR` to `recvit(cp, S_IFDIR)`.
- `settarget()` initializes `catname` and `ptarget`.
- Each nested `C_RECVDIR` stores `ptarget` in `sptarget[catname]`, then increments `catname`.
- With `C_TARGET`, the 33rd nested `C_RECVDIR` writes `sptarget[32]`.
- With `C_DIRTARGET`, the 32nd nested `C_RECVDIR` writes `sptarget[32]` because `catname` starts at 1.

Short directory names avoid `PATH_MAX` preventing the sequence first.

## Why This Is A Real Bug

The array has 32 elements, but the bounds check allows indexes up to the array byte size minus one. This permits an attacker-controlled protocol sequence to perform an out-of-bounds global pointer write before later directory handling can reject or unwind the operation. The result is memory corruption in the `rdistd` process, supporting at least attacker-triggered denial of service and potentially stronger memory-corruption impact.

## Fix Requirement

Compare `catname` against the number of elements in `sptarget`, not the byte size of `sptarget`.

Acceptable forms include:

```c
sizeof(sptarget) / sizeof(sptarget[0])
```

or an equivalent element-count helper such as `nitems(sptarget)` where available.

## Patch Rationale

The patch changes the guard from a byte-size comparison to an element-count comparison:

```diff
-		if ((size_t) catname >= sizeof(sptarget)) {
+		if ((size_t) catname >= sizeof(sptarget) / sizeof(sptarget[0])) {
```

This preserves the existing control flow and error behavior while correctly rejecting `catname == 32` before `sptarget[catname]` is written.

## Residual Risk

None

## Patch

`044-nested-directory-commands-overflow-saved-target-stack.patch`

```diff
diff --git a/usr.bin/rdistd/server.c b/usr.bin/rdistd/server.c
index 7a0f98c..d4ea25b 100644
--- a/usr.bin/rdistd/server.c
+++ b/usr.bin/rdistd/server.c
@@ -1435,7 +1435,7 @@ recvit(char *cmd, int type)
 		 owner, group, file, catname, (type == S_IFDIR) ? 1 : 0);
 
 	if (type == S_IFDIR) {
-		if ((size_t) catname >= sizeof(sptarget)) {
+		if ((size_t) catname >= sizeof(sptarget) / sizeof(sptarget[0])) {
 			error("%s: too many directory levels", target);
 			return;
 		}
```