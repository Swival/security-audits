# Disallowed Stream Mode Becomes Runnable

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

- `usr.bin/sndiod/dev.c:1148`
- `usr.bin/sndiod/dev.c:1476`
- `usr.bin/sndiod/dev.c:1539`
- `usr.bin/sndiod/dev.c:1604`
- `usr.bin/sndiod/dev.c:1687`

## Summary

A local sndio client can request a stream mode forbidden by the selected restricted `opt` while the device is open and not `DEV_CFG`. The mode check in `slot_attach()` rejects the stream before linking it into `d->slot_list`, but `slot_ready()` still marks the slot as `SLOT_RUN`. When the client closes the stream, `slot_stop()` treats the unattached slot as runnable and calls `slot_detach()`, which walks past the end of `d->slot_list` and dereferences NULL in non-DEBUG builds, terminating `sndiod`.

## Provenance

Reported and reproduced from Swival Security Scanner results: https://swival.dev

## Preconditions

- A restricted `opt` exists whose `opt->mode` forbids the requested stream mode.
- The device is already open and `s->opt->dev->pstate != DEV_CFG`.
- The client can create and close a local sndio stream using the restricted `opt`.
- The requested slot mode includes a forbidden mode, for example `MODE_REC` against a play-only `opt`.

## Proof

The reproduced path is:

1. A local sndio client requests a forbidden stream mode through a restricted `opt`.
2. `usr.bin/sndiod/sock.c:908` calls `slot_start()`.
3. For a rec-only requested stream, `usr.bin/sndiod/dev.c:1588` sets `s->pstate = SLOT_READY` and calls `slot_ready(s)`.
4. `usr.bin/sndiod/dev.c:1538` calls `slot_attach(s)`.
5. `slot_attach()` rejects the mode at `usr.bin/sndiod/dev.c:1476` and returns before linking `s` into `d->slot_list` at `usr.bin/sndiod/dev.c:1516`.
6. `slot_ready()` nevertheless sets `s->pstate = SLOT_RUN` at `usr.bin/sndiod/dev.c:1539`.
7. On stream close, `slot_stop()` sees `SLOT_RUN` and calls `slot_detach()` at `usr.bin/sndiod/dev.c:1687`.
8. `slot_detach()` searches for `s` in `d->slot_list`; because the slot was never attached, `*ps` becomes NULL, and the loop update at `usr.bin/sndiod/dev.c:1604` dereferences `(*ps)->next` through NULL in non-DEBUG builds.

The issue was reproduced with a small ASan harness, which crashed in `slot_detach()` at `usr.bin/sndiod/dev.c:1604`.

## Why This Is A Real Bug

The state machine allows an impossible state: `SLOT_RUN` without membership in `d->slot_list`. `slot_detach()` assumes every runnable slot is attached and only checks the missing-list case under `DEBUG`; in production builds, the NULL list terminator is dereferenced. A local client can trigger this path by requesting a mode disallowed by the selected `opt`, then closing the stream, causing a practical local denial of service against `sndiod`.

## Fix Requirement

`slot_attach()` must report whether attachment actually succeeded, and callers must only transition a slot to `SLOT_RUN` after successful attachment. Rejected slots must remain non-runnable so `slot_stop()` does not call `slot_detach()` for a slot absent from `d->slot_list`.

## Patch Rationale

The patch changes `slot_attach()` from `void` to `int`, returning `0` when the requested stream mode is not allowed and `1` after the slot has been linked into `d->slot_list` and initialized. Both direct startup paths now gate `s->pstate = SLOT_RUN` on a successful `slot_attach()` result:

- `mtc_trigger()` only marks MTC-controlled slots runnable after attachment succeeds.
- `slot_ready()` only marks non-MTC slots runnable after attachment succeeds.
- `dev.h` is updated so the function prototype matches the new return type.

This preserves the existing rejection behavior while preventing a rejected, unattached slot from entering `SLOT_RUN`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/sndiod/dev.c b/usr.bin/sndiod/dev.c
index 5ca337f..bf2eff1 100644
--- a/usr.bin/sndiod/dev.c
+++ b/usr.bin/sndiod/dev.c
@@ -1160,8 +1160,8 @@ mtc_trigger(struct mtc *mtc)
 	for (i = 0, s = slot_array; i < DEV_NSLOT; i++, s++) {
 		if (s->opt == NULL || s->opt->mtc != mtc)
 			continue;
-		slot_attach(s);
-		s->pstate = SLOT_RUN;
+		if (slot_attach(s))
+			s->pstate = SLOT_RUN;
 	}
 	mtc->tstate = MTC_RUN;
 	mtc_midi_full(mtc);
@@ -1467,7 +1467,7 @@ slot_setvol(struct slot *s, unsigned int vol)
 /*
  * attach the slot to the device (ie start playing & recording
  */
-void
+int
 slot_attach(struct slot *s)
 {
 	struct dev *d = s->opt->dev;
@@ -1476,7 +1476,7 @@ slot_attach(struct slot *s)
 	if (((s->mode & MODE_PLAY) && !(s->opt->mode & MODE_PLAY)) ||
 	    ((s->mode & MODE_RECMASK) && !(s->opt->mode & MODE_RECMASK))) {
 		logx(1, "slot%zu at %s: mode not allowed", s - slot_array, s->opt->name);
-		return;
+		return 0;
 	}
 
 	/*
@@ -1519,6 +1519,7 @@ slot_attach(struct slot *s)
 		s->mix.vol = MIDI_TO_ADATA(s->app->vol);
 		dev_mix_adjvol(d);
 	}
+	return 1;
 }
 
 /*
@@ -1535,8 +1536,8 @@ slot_ready(struct slot *s)
 	if (s->opt->dev->pstate == DEV_CFG)
 		return;
 	if (s->opt->mtc == NULL) {
-		slot_attach(s);
-		s->pstate = SLOT_RUN;
+		if (slot_attach(s))
+			s->pstate = SLOT_RUN;
 	} else
 		mtc_trigger(s->opt->mtc);
 }
diff --git a/usr.bin/sndiod/dev.h b/usr.bin/sndiod/dev.h
index d942748..0319282 100644
--- a/usr.bin/sndiod/dev.h
+++ b/usr.bin/sndiod/dev.h
@@ -325,7 +325,7 @@ void slot_stop(struct slot *, int);
 void slot_read(struct slot *);
 void slot_write(struct slot *);
 void slot_initconv(struct slot *);
-void slot_attach(struct slot *);
+int slot_attach(struct slot *);
 void slot_detach(struct slot *);
 
 /*
```