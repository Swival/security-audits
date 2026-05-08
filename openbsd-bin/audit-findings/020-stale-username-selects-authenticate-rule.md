# Stale Username Selects Authenticate Rule

## Classification

authorization bypass, medium severity

## Affected Locations

`usr.sbin/radiusd/radiusd.c:525`

## Summary

`radiusd_listen_handle_packet()` uses a static `username[256]` buffer across packets. When a packet lacks `User-Name`, the parse failure is logged but the buffer is not cleared. A subsequent `Access-Request` without `User-Name` can therefore be matched against the previous packet's username and routed through that user's `authenticate` rule.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

- The attacker can send RADIUS `Access-Request` packets from a configured client address.
- Any required client checks are satisfied, including `Message-Authenticator` when configured.
- A prior request has populated the static username buffer with a username that matches an `authenticate` rule.
- A later `Access-Request` omits the `User-Name` attribute.

## Proof

`radiusd_listen_handle_packet()` declares `static char username[256]`, so the buffer persists between invocations.

If `radius_get_string_attr(packet, RADIUS_TYPE_USER_NAME, username, sizeof(username))` fails, the code only logs `no User-Name attribute`. It does not clear `username`.

For an `Access-Request`, the authenticate lookup then immediately evaluates:

```c
fnmatch(authen->username[i], username, 0)
```

The stale username can match an `authenticate` entry. The matched rule is stored in `q->authen`, and processing starts through `raidus_query_access_request(q)`. For modules supporting access-request handling, execution reaches `radiusd_module_access_request()`, so the nameless packet is processed under the stale user's selected policy.

A practical sequence is:

1. Send a valid `Access-Request` with `User-Name = victim_or_privileged_pattern`.
2. Send a second valid `Access-Request` without `User-Name`.
3. The second request is authenticated using the authenticate rule selected by the previous username.

## Why This Is A Real Bug

The authorization decision for `Access-Request` routing is based on the username pattern matched by `fnmatch()`. A packet without `User-Name` should not inherit identity-routing state from an earlier packet. Because the buffer is static and not reset on parse failure, the daemon applies a previous request's username to a distinct request, producing a concrete authorization-policy bypass.

## Fix Requirement

Ensure each packet's username state is independent. At minimum, clear `username` before parsing the `User-Name` attribute. Alternatively, reject `Access-Request` packets that lack `User-Name`.

## Patch Rationale

The patch resets the static username buffer before attempting to parse the current packet:

```c
username[0] = '\0';
```

This guarantees that if `radius_get_string_attr()` fails, later authenticate and accounting rule matching uses an empty string rather than stale data from a previous packet. Existing logging and control flow remain unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/radiusd/radiusd.c b/usr.sbin/radiusd/radiusd.c
index 94a1b26..7cd01bd 100644
--- a/usr.sbin/radiusd/radiusd.c
+++ b/usr.sbin/radiusd/radiusd.c
@@ -529,6 +529,7 @@ radiusd_listen_handle_packet(struct radiusd_listen *listn,
 		log_warn("%s: Out of memory", __func__);
 		goto on_error;
 	}
+	username[0] = '\0';
 	if (radius_get_string_attr(packet, RADIUS_TYPE_USER_NAME, username,
 	    sizeof(username)) != 0) {
 		log_info("Received %s(code=%d) from %s id=%d: no User-Name "
```