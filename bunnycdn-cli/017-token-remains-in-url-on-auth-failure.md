# Token Remains In URL On Auth Failure

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`packages/database-studio/client/src/main.tsx:16`

## Summary

`exchangeToken()` reads an authentication token from `window.location.search` and posts it to `/api/auth`, but the token is removed from the browser URL only inside a `.then(...)` callback. If `fetch()` rejects due to a network-level failure, the callback is skipped and the token remains visible in the location bar, browser history, and possible bookmarks.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The page is opened with a `token` query parameter.
- `/api/auth` exchange fails by rejection, such as connection failure, proxy/network failure, interrupted request, or server unavailability during the exchange.

## Proof

The affected code obtains the token from the URL:

```ts
const params = new URLSearchParams(window.location.search);
const token = params.get("token");
```

It sends that token to `/api/auth`:

```ts
return fetch("/api/auth", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token }),
  credentials: "same-origin",
})
```

Before the patch, URL scrubbing occurred only in `.then(...)`:

```ts
}).then(() => {
  params.delete("token");
  const qs = params.toString();
  const newUrl =
    window.location.pathname + (qs ? `?${qs}` : "") + window.location.hash;
  window.history.replaceState({}, "", newUrl);
});
```

Browser `fetch()` resolves for HTTP error responses such as `400`, `401`, or `500`, so those statuses still executed `.then(...)`. However, rejected fetches skip `.then(...)`. Because `exchangeToken()` is called before rendering and has no `.catch(...)` or `.finally(...)` at the call site, a rejected auth request leaves the token-bearing URL unchanged.

## Why This Is A Real Bug

The code comment states that the token should be scrubbed from the URL so it does not linger in history or bookmarks. The implementation fails to guarantee that behavior on rejected auth exchanges. An auto-opened `/?token=...` URL can therefore retain a startup authentication token in user-visible browser state after a realistic network-level failure.

## Fix Requirement

Scrub the `token` parameter regardless of auth exchange success or failure, while preserving the token value long enough to send it in the `/api/auth` POST body.

## Patch Rationale

Changing `.then(...)` to `.finally(...)` preserves the existing request behavior and guarantees that the URL cleanup runs after `fetch()` settles, whether it resolves or rejects. The token is still captured before the request and remains available for the POST body.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-studio/client/src/main.tsx b/packages/database-studio/client/src/main.tsx
index e16533f..537e97a 100644
--- a/packages/database-studio/client/src/main.tsx
+++ b/packages/database-studio/client/src/main.tsx
@@ -16,7 +16,7 @@ function exchangeToken(): Promise<void> {
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({ token }),
     credentials: "same-origin",
-  }).then(() => {
+  }).finally(() => {
     params.delete("token");
     const qs = params.toString();
     const newUrl =
```