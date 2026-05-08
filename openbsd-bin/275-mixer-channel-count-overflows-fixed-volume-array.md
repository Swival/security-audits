# mixer channel count overflows fixed volume array

## Classification

Medium severity out-of-bounds write / memory corruption in a libsndio client process.

Confidence: certain.

## Affected Locations

- `lib/libsndio/sioctl_sun.c:47`
- `lib/libsndio/sioctl_sun.c:123`
- `lib/libsndio/sioctl_sun.c:245`
- `lib/libsndio/sioctl_sun.c:254`
- `lib/libsndio/sioctl_sun.c:258`
- `lib/libsndio/sioctl_sun.c:422`

## Summary

`initvol()` trusted `AUDIO_MIXER_DEVINFO` metadata and copied `dev.un.v.num_channels` directly into `vol->nch`. `struct volume` stores cached levels in `level_val[8]`, but later volume scan and update paths iterate to `vol->nch` and index `vol->level_val[i]`.

An attacker-controlled audioctl backend that reports more than eight channels for a whitelisted mixer value can cause out-of-bounds access and memory corruption in the libsndio client process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with a fake ioctl harness that returned a matching mixer value with `num_channels = 9`.

## Preconditions

- The client opens an attacker-controlled audioctl device or backend.
- The backend reports a whitelisted mixer value such as `outputs.master`.
- The mixer metadata sets `dev.un.v.num_channels` greater than eight.
- The backend returns success for `AUDIO_MIXER_READ`.

## Proof

`struct volume` defines fixed storage for cached mixer levels:

```c
int level_val[8];		/* current value */
```

Before the patch, `initvol()` accepted the backend-reported channel count without validating it against that array:

```c
vol->nch = dev.un.v.num_channels;
```

`sioctl_sun_ondesc()` calls `scanvol()` for output and input controls. In `scanvol()`, the trusted count is reused:

```c
ctrl.un.value.num_channels = vol->nch;
```

The function then iterates over all reported channels:

```c
for (i = 0; i < vol->nch; i++) {
	desc.node0.unit = i;
	desc.addr = vol->base_addr + i;
	val = ctrl.un.value.level[i];
	vol->level_val[i] = val;
	_sioctl_ondesc_cb(&hdl->sioctl, &desc, val);
}
```

With `vol->nch = 9`, the loop reaches index `8`, which is outside `level_val[8]`. The reproducer reached this vulnerable loop; ASan stopped at the adjacent `ctrl.un.value.level[8]` read immediately before the proven `vol->level_val[8]` out-of-bounds write.

## Why This Is A Real Bug

The fixed-size destination has eight elements, while the loop bound comes from attacker-controlled mixer metadata. There was no cap or rejection before the value was stored in `vol->nch`.

The same unchecked `vol->nch` also affects related paths such as `setvol()` and `updatevol()`, which use `vol->level_val[i]` and mixer level arrays with the same untrusted bound.

Because the bug is reachable during descriptor enumeration via `sioctl_sun_ondesc()`, a client that opens the malicious backend and fetches descriptions can trigger memory corruption without needing unusual application behavior.

## Fix Requirement

Reject or clamp mixer values whose reported channel count exceeds the fixed `struct volume.level_val` capacity.

The fix must ensure `vol->nch` is never greater than the number of elements in `vol->level_val`.

## Patch Rationale

The patch rejects oversized mixer value descriptors during `initvol()` before assigning `dev.un.v.num_channels` to `vol->nch`.

```diff
+			if (dev.un.v.num_channels >
+			    (int)(sizeof(vol->level_val) / sizeof(vol->level_val[0])))
+				continue;
 			vol->nch = dev.un.v.num_channels;
```

Rejecting the descriptor preserves the invariant that every later loop bounded by `vol->nch` remains within `vol->level_val`. It also avoids silently truncating a backend-reported control, which could otherwise create inconsistent behavior between the library and the backend.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libsndio/sioctl_sun.c b/lib/libsndio/sioctl_sun.c
index 886c820..5932d9d 100644
--- a/lib/libsndio/sioctl_sun.c
+++ b/lib/libsndio/sioctl_sun.c
@@ -120,6 +120,9 @@ initvol(struct sioctl_sun_hdl *hdl, struct volume *vol, char *cn, char *dn)
 			break;
 		if (strcmp(cls.label.name, cn) == 0 &&
 		    strcmp(dev.label.name, dn) == 0) {
+			if (dev.un.v.num_channels >
+			    (int)(sizeof(vol->level_val) / sizeof(vol->level_val[0])))
+				continue;
 			vol->nch = dev.un.v.num_channels;
 			vol->level_idx = dev.index;
 			vol->mute_idx = initmute(hdl, &dev);
```