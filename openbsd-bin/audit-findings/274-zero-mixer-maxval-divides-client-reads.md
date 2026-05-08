# zero mixer maxval divides client reads

## Classification

Denial of service, medium severity.

## Affected Locations

`lib/libossaudio/ossaudio.c:294`

## Summary

`libossaudio` accepts attacker-supplied sndio numeric mixer descriptors with `maxval == 0`. It stores that value as `c->max`, then later divides by `c->max` during OSS mixer reads. A malicious sndio control backend can therefore make OSS-emulated clients terminate with `SIGFPE`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The client uses `libossaudio`.
- The client connects to attacker-controlled `sioctl` descriptors, such as through a malicious sndio control backend.
- The malicious descriptor is a supported numeric `level` control for an accepted input/output mixer path.
- The malicious descriptor advertises `maxval == 0`.

## Proof

A malicious sndio peer can control descriptor fields. The `snd@host` path is supported, and `sioctl_aucat_rdata()` copies `maxval` directly from the wire into `desc.maxval` at `lib/libsndio/sioctl_aucat.c:93`.

`mixer_ondesc()` accepts numeric `level` controls for top-level `output`/`input` and `hw/output`/`hw/input` without validating `maxval` at `lib/libossaudio/ossaudio.c:115`.

The accepted descriptor value is stored directly:

```c
i->max = d->maxval;
```

During an OSS mixer read, the default `MIXER_READ` path computes:

```c
v = (c->value * 100 + c->max / 2) / c->max;
```

If the backend supplies `maxval == 0`, then `c->max == 0`, so `SOUND_MIXER_READ_VOLUME` or another matching mixer read performs integer division by zero and raises `SIGFPE` in the client process.

A concrete malicious descriptor is:

```text
type=SIOCTL_NUM
func="level"
group=""
node0.name="output"
node0.unit=0
maxval=0
```

## Why This Is A Real Bug

The read path is reachable through normal OSS mixer ioctls after descriptor registration. The denominator is fully derived from a remote descriptor field and is not checked before storage or use. Integer division by zero is undefined behavior in C and practically terminates the affected process with `SIGFPE`, producing a reliable client-side denial of service.

## Fix Requirement

Reject or safely clamp numeric mixer descriptors with `maxval == 0` before storing them as usable controls.

## Patch Rationale

The patch rejects unsupported numeric `level` controls whose advertised maximum is zero. This prevents `c->max` from ever being initialized to zero for accepted controls, removing the division-by-zero condition in both readback after writes and direct mixer reads.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libossaudio/ossaudio.c b/lib/libossaudio/ossaudio.c
index bad73ac..da566b3 100644
--- a/lib/libossaudio/ossaudio.c
+++ b/lib/libossaudio/ossaudio.c
@@ -113,7 +113,7 @@ mixer_ondesc(void *unused, struct sioctl_desc *d, int val)
 	 * we support only numeric "level" controls, first 2 channels
 	 */
 	if (d->type != SIOCTL_NUM || d->node0.unit >= 2 ||
-	    strcmp(d->func, "level") != 0)
+	    d->maxval == 0 || strcmp(d->func, "level") != 0)
 		return;
 
 	/*
```