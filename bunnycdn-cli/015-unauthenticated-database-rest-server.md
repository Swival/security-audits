# unauthenticated database REST server

## Classification

Authorization flaw, medium severity. Confidence: certain.

## Affected Locations

`packages/database-rest/dev.ts:40`

## Summary

`packages/database-rest/dev.ts` starts a database REST dev server by passing every incoming request directly to `createRestHandler(executor, schema)`. When the server is reachable by an untrusted client, unauthenticated callers can invoke REST mutation routes and modify the backing database.

The patch adds a required bearer-token gate before dispatching requests to the REST handler.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

The dev server is reachable by an untrusted network client, including through explicit host configuration, proxying, port forwarding, or an untrusted local client.

## Proof

The affected file constructs the REST handler and exposes it directly:

```ts
const handler = createRestHandler(executor, schema);

const port = Number(process.env.PORT) || 8080;
const server = Bun.serve({ port, fetch: handler });
```

The same dev server advertises unauthenticated mutation examples for `POST`, `PATCH`, and `DELETE` against `/users`.

Runtime reproduction confirmed the issue:

```bash
PORT=18080 bun packages/database-rest/dev.ts

curl -i -X POST http://127.0.0.1:18080/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Mallory","email":"mallory@example.com","age":66}'
```

The unauthenticated request returned:

```text
HTTP/1.1 201 Created
```

A follow-up query showed the inserted row:

```json
{"data":[{"id":4,"name":"Mallory","email":"mallory@example.com","age":66,"created_at":"..."}]}
```

Mutation behavior is reachable because `packages/database-rest/src/handler.ts:143` allows single-row `PATCH` and `DELETE`, and mutation handlers call SQL builders and `executor.execute(...)` directly, including insert handling at `packages/database-rest/src/handler.ts:249`.

## Why This Is A Real Bug

The server exposes database mutation endpoints without any authentication or authorization check. Any client that can reach the Bun server can create, update, or delete database rows. The issue is not theoretical: an unauthenticated `POST /users` request successfully inserted a row and returned `201 Created`.

Although this is a dev server, the vulnerable condition exists whenever it is reachable by an untrusted client.

## Fix Requirement

Require authentication and authorization before invoking the handler returned by `createRestHandler(executor, schema)`. Unauthenticated requests must be rejected before database REST routing or SQL execution occurs.

## Patch Rationale

The patch requires `DATABASE_REST_AUTH_TOKEN` to be set before the dev server starts. It wraps the Bun `fetch` handler and checks:

```ts
Authorization: Bearer <DATABASE_REST_AUTH_TOKEN>
```

Requests without the exact bearer token receive `401 Unauthorized` and are not passed to the database REST handler. Authorized requests continue to use the existing handler unchanged.

This directly addresses the vulnerable trust boundary at `Bun.serve`.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/dev.ts b/packages/database-rest/dev.ts
index 3654f24..c814c4e 100644
--- a/packages/database-rest/dev.ts
+++ b/packages/database-rest/dev.ts
@@ -35,9 +35,22 @@ await client.executeMultiple(`
 const schema = await introspect({ client });
 const executor = createLibSQLExecutor({ client });
 const handler = createRestHandler(executor, schema);
+const authToken = process.env.DATABASE_REST_AUTH_TOKEN;
+if (!authToken) {
+  throw new Error("DATABASE_REST_AUTH_TOKEN must be set to run dev server");
+}
 
 const port = Number(process.env.PORT) || 8080;
-const server = Bun.serve({ port, fetch: handler });
+const server = Bun.serve({
+  port,
+  fetch: (request) => {
+    if (request.headers.get("Authorization") !== `Bearer ${authToken}`) {
+      return new Response("Unauthorized", { status: 401 });
+    }
+
+    return handler(request);
+  },
+});
 
 console.log(`Listening on http://localhost:${server.port}`);
 console.log();
```