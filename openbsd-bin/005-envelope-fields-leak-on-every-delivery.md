# Envelope Fields Leak On Every Delivery

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`smtpd/mda.c:850`

## Summary

The MDA process leaks per-envelope heap allocations for `dispatcher` and optional `mda_subaddress` on every accepted local delivery. Repeated local deliveries can grow the long-lived MDA heap until allocation failure makes local delivery unavailable.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Server accepts attacker-controlled messages for local MDA delivery.

## Proof

`IMSG_QUEUE_DELIVER` creates an MDA envelope for each accepted local delivery by calling `mda_envelope()`.

In `mda_envelope()`, the envelope duplicates two fields into heap-owned storage:

```c
e->dispatcher = xstrdup(evp->dispatcher);
...
if (evp->mda_subaddress[0])
	e->mda_subaddress = xstrdup(evp->mda_subaddress);
```

All completion paths free the envelope through `mda_envelope_free()`:

- successful delivery reaches `mda_envelope_free()` through `mda_done()`
- user lookup failure reaches `mda_envelope_free()` through `mda_fail()`

Before the patch, `mda_envelope_free()` released only:

```c
free(e->sender);
free(e->dest);
free(e->rcpt);
free(e->user);
free(e->mda_exec);
free(e);
```

It omitted `e->dispatcher` and `e->mda_subaddress`, so those allocations leaked after both successful and failed delivery completion.

Subaddresses are attacker-influenced through recipient local parts and are copied into the MDA envelope. Repeated accepted local deliveries therefore consume additional heap in the long-lived MDA process. Allocation failure in this code path is fatal because `xstrdup()` aborts on failure.

## Why This Is A Real Bug

The ownership model is clear: `mda_envelope()` allocates `dispatcher` and `mda_subaddress` with `xstrdup()`, and `mda_envelope_free()` is the destructor for the same `struct mda_envelope`. Every heap member allocated by the constructor must be released by the destructor.

The leak is reachable remotely when the server accepts messages for local delivery. It accumulates across completed deliveries because the MDA process is long-lived, making this a real denial-of-service condition rather than a bounded transient allocation.

## Fix Requirement

Free `e->dispatcher` and `e->mda_subaddress` in `mda_envelope_free()` before freeing the envelope structure.

## Patch Rationale

The patch adds the two missing frees to the existing envelope destructor:

```c
free(e->dispatcher);
free(e->mda_subaddress);
```

This matches the allocations performed by `mda_envelope()` and preserves the existing cleanup order. `free(NULL)` is safe, so the conditional nature of `mda_subaddress` allocation requires no extra guard.

## Residual Risk

None

## Patch

```diff
diff --git a/smtpd/mda.c b/smtpd/mda.c
index c9ba83c..5cf8449 100644
--- a/smtpd/mda.c
+++ b/smtpd/mda.c
@@ -821,6 +821,8 @@ mda_envelope_free(struct mda_envelope *e)
 	free(e->dest);
 	free(e->rcpt);
 	free(e->user);
+	free(e->dispatcher);
+	free(e->mda_subaddress);
 	free(e->mda_exec);
 	free(e);
```