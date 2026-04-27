# Unauthenticated Database CRUD Handler

## Classification

Authorization flaw, medium severity. Confidence: certain.

## Affected Locations

`packages/database-rest/src/handler.ts:116`

## Summary

`createRestHandler` accepts arbitrary HTTP requests, parses the requested table route, and dispatches `GET`, `POST`, `PATCH`, and `DELETE` operations directly to database CRUD handlers without requiring authentication or authorization. If exposed to untrusted clients, any schema-routable table can be read, inserted into, updated, or deleted.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

`createRestHandler` is exposed to untrusted HTTP clients.

## Proof

The returned handler builds `url` from `req.url`, strips `basePath`, serves OpenAPI metadata for `GET /`, then parses the route with `parseRoute(pathname, tableNames)`.

After a valid route is found, the handler dispatches directly by HTTP method:

- Collection routes call `handleGet`, `handlePost`, `handlePatch`, or `handleDelete`.
- Single-resource routes call `handleGetOne`, `handlePatchOne`, or `handleDeleteOne`.

Those handlers build SQL via `buildSelectQuery`, `buildCountQuery`, `buildInsertQuery`, `buildUpdateQuery`, or `buildDeleteQuery`, then call `executor.execute(...)`. No authentication or authorization check exists before these database operations.

Practical triggers for any schema-routable table include:

- `GET /users` reads rows and count metadata.
- `POST /users` inserts attacker-supplied rows.
- `PATCH /users/1` or `PATCH /users?id=eq.1` updates matching rows.
- `DELETE /users/1` or `DELETE /users?id=eq.1` deletes matching rows.

The README demonstrates direct exposure with `const handler = createRestHandler(...)` and `Bun.serve({ port: 8080, fetch: handler })`, making the unauthenticated path practically reachable when copied without an external wrapper.

## Why This Is A Real Bug

The security decision is absent at the library boundary where database-changing actions are performed. Although another package wraps this handler with authentication, that caller-side protection does not secure direct uses of `createRestHandler`. The exported handler itself is capable of unauthenticated CRUD if mounted as shown in the package quick start.

## Fix Requirement

Require an authorization callback before dispatching any CRUD handler. Requests without an authorization callback must fail closed, and requests denied by the callback must not reach SQL construction or `executor.execute`.

## Patch Rationale

The patch adds `authorize?: (req: Request, route: ParsedRoute) => boolean | Promise<boolean>` to `RestHandlerOptions`, extracts it in `createRestHandler`, and checks it after route parsing but before CRUD dispatch.

Behavior after patch:

- Missing `authorize` returns `401 Unauthorized`.
- Present `authorize` returning false returns `403 Forbidden`.
- Only authorized requests continue to `handleGet`, `handlePost`, `handlePatch`, `handleDelete`, `handleGetOne`, `handlePatchOne`, or `handleDeleteOne`.

This fails closed for database routes and centralizes the security gate before all read and write paths.

## Residual Risk

None

## Patch

```diff
diff --git a/packages/database-rest/src/handler.ts b/packages/database-rest/src/handler.ts
index 58c332c..f67d593 100644
--- a/packages/database-rest/src/handler.ts
+++ b/packages/database-rest/src/handler.ts
@@ -18,6 +18,8 @@ export interface RestHandlerOptions {
   basePath?: string;
   /** Options passed to generateOpenAPISpec for the root endpoint. */
   openapi?: GenerateOptions;
+  /** Required authorization check for database CRUD requests. */
+  authorize?: (req: Request, route: ParsedRoute) => boolean | Promise<boolean>;
 }
 
 const json = (data: unknown, status = 200, headers?: Record<string, string>) =>
@@ -83,7 +85,7 @@ export const createRestHandler = (
   schema: DatabaseSchema,
   options: RestHandlerOptions = {},
 ) => {
-  const { basePath = "" } = options;
+  const { authorize, basePath = "" } = options;
   const spec = generateOpenAPISpec(schema, options.openapi);
   const tableNames = new Set(Object.keys(schema.tables));
 
@@ -134,6 +136,13 @@ export const createRestHandler = (
     }
 
     try {
+      if (!authorize) {
+        return errorResponse("Unauthorized", 401, "UNAUTHORIZED");
+      }
+      if (!(await authorize(req, route))) {
+        return errorResponse("Forbidden", 403, "FORBIDDEN");
+      }
+
       if (route.kind === "single") {
         const column = resolveSingleColumn(route);
         if (!column) {
```