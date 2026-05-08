# Duplicate Content-Length Enables Request Smuggling

## Classification

Request smuggling, high severity, certain confidence.

## Affected Locations

`usr.sbin/relayd/relay_http.c:398`

## Summary

`relayd` accepted multiple `Content-Length` headers, used the last parsed value to decide how many body bytes to relay, and forwarded all duplicate `Content-Length` headers to the backend. If the backend honors the first `Content-Length`, relay and backend disagree on the request boundary, allowing an embedded request to bypass relay-side HTTP filtering.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Backend honors the first `Content-Length` header when duplicate `Content-Length` values differ.
- Attacker can send a remote HTTP request through `relayd`.
- Backend connection is reusable or otherwise processes bytes following the backend’s first interpreted request body.

## Proof

The relay parses every header line and only treated `Host` as unique before storing headers with `kv_add`. Duplicate `Content-Length` headers were therefore accepted.

For each parsed `Content-Length`, the relay updated `cre->toread` with `strtonum(value)`, so the last `Content-Length` controlled how many body bytes `relay_read_httpcontent` forwarded as part of the current request.

Later, `relay_writeheader_http` emitted every stored header, including duplicate parent and child headers, preserving duplicate `Content-Length` values to the backend.

Concrete trigger:

```http
POST /allowed HTTP/1.1
Host: victim
Content-Length: 0
Content-Length: 39

GET /blocked HTTP/1.1
Host: victim

```

Relay interpretation:

- Last `Content-Length` is `39`.
- The embedded `GET /blocked` bytes are treated as the POST body.
- Relay-side filters evaluate only the visible `POST /allowed` request.

First-value backend interpretation:

- First `Content-Length` is `0`.
- The POST has no body.
- The following 39 bytes become the next backend request: `GET /blocked`.

## Why This Is A Real Bug

This creates a concrete parser differential between relay and backend. The relay uses the last `Content-Length` to frame the request body but forwards both conflicting headers. A first-value backend uses a different boundary and treats bytes the relay classified as body data as a separate HTTP request. That separate backend request can bypass relay-side method, path, URL, header, or cookie filtering because the relay did not parse it as a request before forwarding it as body bytes.

## Fix Requirement

Reject duplicate `Content-Length` headers, or accept duplicates only when all values are identical and normalize forwarding so relay and backend cannot disagree on request framing.

## Patch Rationale

The patch marks `Content-Length` as a unique header alongside `Host` before calling `kv_add`.

```diff
-		/* The "Host" header must only occur once. */
-		unique = strcasecmp("Host", key) == 0;
+		/* These headers must only occur once. */
+		unique = strcasecmp("Host", key) == 0 ||
+		    strcasecmp("Content-Length", key) == 0;
```

With `unique` set for `Content-Length`, `kv_add` rejects duplicate `Content-Length` headers as malformed instead of storing and forwarding them. This removes the relay/backend framing ambiguity at the source.

## Residual Risk

None

## Patch

`012-duplicate-content-length-forwarded-while-last-value-controls.patch`