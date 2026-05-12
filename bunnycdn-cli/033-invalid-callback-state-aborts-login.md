# Invalid Callback State Aborts Login

## Classification

Denial of service, low severity. Confidence: certain.

## Affected Locations

`packages/cli/src/commands/auth/login.ts:109`

## Summary

The CLI login flow starts a loopback callback server on `127.0.0.1` and waits for a browser callback containing a valid `state` and `apiKey`. Before the patch, any local request to `/callback` with an incorrect `state` rejected the pending login promise, causing the CLI to log an authentication failure and exit. A lower-privileged local user could scan loopback ports and abort another user's active login attempt.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Victim is actively running `auth login`.
- Attacker can connect to `127.0.0.1` ports on the same host.
- Attacker can discover or scan the ephemeral loopback port during the login window.

## Proof

The callback server is created on `127.0.0.1` with a random ephemeral port and the login flow awaits `Promise.race([apiKeyPromise, timeout])`.

The `/callback` handler parses `state` and `apiKey` from the query string. Before the patch, when `returnedState !== state`, the handler executed:

```ts
reject(new Error("State mismatch: possible CSRF attack"));
```

That rejected the same `apiKeyPromise` that the login flow was awaiting. The rejection propagated to the surrounding `catch`, logged `Authentication failed: State mismatch: possible CSRF attack`, and terminated the CLI with `process.exit(1)` before a legitimate dashboard callback could complete authentication and write the profile.

A local attacker request such as:

```http
GET /callback?state=wrong HTTP/1.1
Host: 127.0.0.1:<discovered-port>
```

deterministically aborted the victim's active login flow.

## Why This Is A Real Bug

The invalid callback is attacker-controlled local input. It should be rejected as an invalid request, but it should not terminate the pending authentication session. The original behavior let any loopback client convert a harmless bad-state probe into a denial of service against the victim's current login attempt.

The impact is bounded to the active login session and does not expose credentials, so the severity is low.

## Fix Requirement

For callbacks with an invalid `state`, return `400 Invalid state parameter` without rejecting or resolving the pending login promise. The login flow should remain active until one of these occurs:

- a valid callback supplies the expected state and API key;
- another terminal validation error occurs for a valid callback;
- the authentication timeout expires.

## Patch Rationale

The patch removes the promise rejection from the bad-state branch while preserving the HTTP `400` response. CSRF/state validation remains intact for the incoming request, but unrelated local probes can no longer abort the whole login flow. The `apiKey`-missing branch still rejects, since reaching it requires a callback with the correct (random) state, which is not attacker-guessable.

## Residual Risk

None.

## Patch

```diff
diff --git a/packages/cli/src/commands/auth/login.ts b/packages/cli/src/commands/auth/login.ts
index 811c2a8..9483af4 100644
--- a/packages/cli/src/commands/auth/login.ts
+++ b/packages/cli/src/commands/auth/login.ts
@@ -105,7 +105,6 @@ export const authLoginCommand = defineCommand<{ force: boolean }>({
         const apiKey = url.searchParams.get("apiKey");
 
         if (returnedState !== state) {
-          reject(new Error("State mismatch: possible CSRF attack"));
           return new Response("Invalid state parameter.", {
             status: 400,
             headers: NO_STORE,
```
