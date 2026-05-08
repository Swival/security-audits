# child instance uid inherits gid

## Classification

Authorization bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/vmd/vmd.c:1282`

## Summary

When `vmd` creates a child VM instance with inherited instance permissions, it copies the parent instance-owner group into both the child `vmc_insowner.gid` and `vmc_insowner.uid`. This corrupts the inherited UID permission. A later caller whose UID numerically equals the configured group ID can pass the UID equality check and create a further unauthorized VM instance.

## Provenance

Verified from supplied source, reproduced control-flow analysis, and patched finding data. Scanner provenance: [Swival Security Scanner](https://swival.dev).

## Preconditions

- Parent VM permits child instances.
- Parent VM has nonzero `insowner.gid`.
- Parent `insowner.gid` numerically matches an attacker UID.
- Attacker has control-socket access.
- Attacker is not the intended instance owner and is not a member of the allowed group.

## Proof

`vmd_dispatch_control` handles `IMSG_VMDOP_START_VM_REQUEST` and calls `vm_register` with the requesting UID.

`vm_register` calls `vm_instance` for `VMOP_CREATE_INSTANCE` requests. In `vm_instance`, child instance permissions are inherited from the parent:

```c
if (vmc_parent->vmc_insflags & VMOP_CREATE_INSTANCE) {
	vmc->vmc_insowner.gid = vmc_parent->vmc_insowner.gid;
	vmc->vmc_insowner.uid = vmc_parent->vmc_insowner.gid;
	vmc->vmc_insflags = vmc_parent->vmc_insflags;
}
```

The second assignment incorrectly stores the parent GID in the child UID field.

A later instance creation from this child reaches:

```c
if (vm_checkperm(NULL, &vmc_parent->vmc_insowner, uid) != 0)
```

`vm_checkperm` authorizes direct UID equality before group membership checks:

```c
if (vm == NULL) {
	if  (vmo->uid == uid)
		return (0);
}
```

Therefore, if an attacker UID equals the inherited parent GID, the attacker is accepted as the instance owner even though the intended parent UID was different and the attacker is not in the configured group.

Concrete reproduced trigger:

- Parent template allows instances.
- Parent has inherited instance permissions with `owner :group`.
- That group’s GID equals the attacker UID.
- A legitimate child instance is created from the parent.
- The attacker starts another instance from the child.
- Authorization succeeds through corrupted `vmc_insowner.uid`.

## Why This Is A Real Bug

The code intends to preserve the parent instance owner across inherited child instance permissions. Instead, it writes `vmc_parent->vmc_insowner.gid` into `vmc->vmc_insowner.uid`, mixing identity namespaces. Because `vm_checkperm` treats UID equality as sufficient authorization, a numeric GID collision with an unrelated local UID grants permission that was never configured.

This is not only a reporting inconsistency: the corrupted owner is used in the registration path, allowing unauthorized VM instance creation and use of inherited parent resources if normal resource validation succeeds.

## Fix Requirement

Assign the child inherited instance-owner UID from the parent instance-owner UID, not from the parent instance-owner GID.

## Patch Rationale

The patch restores field-for-field inheritance:

- `vmc_insowner.gid` continues to inherit from `vmc_parent->vmc_insowner.gid`.
- `vmc_insowner.uid` now inherits from `vmc_parent->vmc_insowner.uid`.
- `vmc_insflags` inheritance remains unchanged.

This preserves the configured authorization semantics and prevents numeric GID values from becoming UID grants.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vmd.c b/usr.sbin/vmd/vmd.c
index 0a8b696..bd63a7d 100644
--- a/usr.sbin/vmd/vmd.c
+++ b/usr.sbin/vmd/vmd.c
@@ -1429,7 +1429,7 @@ vm_instance(struct privsep *ps, struct vmd_vm **vm_parent,
 	}
 	if (vmc_parent->vmc_insflags & VMOP_CREATE_INSTANCE) {
 		vmc->vmc_insowner.gid = vmc_parent->vmc_insowner.gid;
-		vmc->vmc_insowner.uid = vmc_parent->vmc_insowner.gid;
+		vmc->vmc_insowner.uid = vmc_parent->vmc_insowner.uid;
 		vmc->vmc_insflags = vmc_parent->vmc_insflags;
 	} else {
 		vmc->vmc_insowner.gid = 0;
```