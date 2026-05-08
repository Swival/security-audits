# Cached Delta Skips Notification Delta Cap

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/rpki-client/rrdp_notification.c:192`

## Summary

A malicious RRDP repository can force unbounded notification-delta allocations when the client has cached repository deltas. The notification parser only applies the `MAX_RRDP_DELTAS` serial floor when `nxml->min_serial == 0`; cached state sets `min_serial` to a nonzero value, so the cap is skipped and every contiguous attacker-supplied delta above the cached minimum is queued before later pruning or snapshot fallback.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client has cached repository deltas.
- `delta_parse(repository, 0, NULL)` returns a nonzero serial.
- The attacker controls the RRDP repository notification XML.
- The attacker supplies many valid, contiguous high-serial `<delta>` elements.

## Proof

`new_notification_xml()` initializes `nxml->min_serial` from cached repository state:

```c
nxml->min_serial = delta_parse(repository, 0, NULL);
```

`start_notification_elem()` intended to cap retained deltas to the relevant window:

```c
if (nxml->min_serial == 0 && nxml->serial > MAX_RRDP_DELTAS)
	nxml->min_serial = nxml->serial - MAX_RRDP_DELTAS;
```

Because cached state makes `min_serial` nonzero, this cap is skipped.

`start_delta_elem()` then accepts every delta whose serial is above `min_serial`:

```c
if (nxml->min_serial < delta_serial) {
	if (add_delta(nxml, delta_uri, delta_hash, delta_serial) == 0)
		PARSE_FAIL(p, "parse failed - adding delta failed");
}
```

`add_delta()` allocates one `struct delta_item` and duplicates the attacker-supplied URI before later validation, pruning, or snapshot fallback:

```c
if ((d = calloc(1, sizeof(struct delta_item))) == NULL)
	err(1, "%s - calloc", __func__);

d->uri = xstrdup(uri);
```

A concrete trigger is cached state with first cached delta serial `701`, followed by a notification with a valid snapshot and contiguous deltas `702..1000000`. Since `min_serial` is nonzero, the parser does not raise it to `notification_serial - MAX_RRDP_DELTAS`; it queues one delta per element during parsing.

## Why This Is A Real Bug

The resource cap exists but is conditional on the absence of cached state. Cached state is the normal case for an updating RRDP client, and it makes the parser trust an older lower bound instead of the notification’s bounded delta window. Allocation occurs during XML parsing, while `check_delta()`, `notification_check_deltas()`, pruning, and snapshot fallback happen only later. On allocation failure, `calloc()` or `xstrdup()` terminates the process via `err(1)`; otherwise, memory consumption grows with attacker-supplied delta count.

## Fix Requirement

Always enforce a minimum serial floor of at least `notification_serial - MAX_RRDP_DELTAS` when the notification serial exceeds `MAX_RRDP_DELTAS`, regardless of whether `min_serial` came from cached repository state.

## Patch Rationale

The patch changes the cap from “only if no cached minimum exists” to “raise the cached minimum if it is lower than the bounded window.” This preserves the cached-state optimization when it is already stricter, while preventing older cached state from expanding the accepted delta set beyond `MAX_RRDP_DELTAS`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpki-client/rrdp_notification.c b/usr.sbin/rpki-client/rrdp_notification.c
index 755c205..050c034 100644
--- a/usr.sbin/rpki-client/rrdp_notification.c
+++ b/usr.sbin/rpki-client/rrdp_notification.c
@@ -194,7 +194,8 @@ start_notification_elem(struct notification_xml *nxml, const char **attr)
 		    "notification attributes");
 
 	/* Limit deltas to the ones which matter for us. */
-	if (nxml->min_serial == 0 && nxml->serial > MAX_RRDP_DELTAS)
+	if (nxml->serial > MAX_RRDP_DELTAS &&
+	    nxml->min_serial < nxml->serial - MAX_RRDP_DELTAS)
 		nxml->min_serial = nxml->serial - MAX_RRDP_DELTAS;
 
 	nxml->scope = NOTIFICATION_SCOPE_NOTIFICATION;
```