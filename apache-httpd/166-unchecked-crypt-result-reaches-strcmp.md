# unchecked crypt result reaches strcmp

## Classification

error-handling bug; medium severity; confidence certain.

## Affected Locations

`modules/lua/lua_passwd.c:138`

## Summary

When `ALG_CRYPT` is selected and the input password is longer than 8 characters, `mk_password_hash()` calls `crypt(truncpw, salt)` and passes the result directly to `strcmp()`. `crypt()` may return `NULL` on error, so this path can pass a `NULL` second argument to `strcmp()`, causing undefined behavior and typically a worker crash.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and patch evidence.

## Preconditions

- `ALG_CRYPT` is selected.
- The password length exceeds 8 characters.
- The second `crypt(truncpw, salt)` call returns `NULL`.

## Proof

The reproduced flow is:

- `request.c:1003` lets Lua select the password algorithm.
- `modules/lua/lua_passwd.h:36` defines `ALG_CRYPT` as selectable.
- `modules/lua/lua_passwd.c:123` calls `crypt(pw, salt)` and checks for `NULL`.
- `modules/lua/lua_passwd.c:132` enters the truncation-warning path for passwords longer than 8 bytes.
- `modules/lua/lua_passwd.c:135` calls `strcmp(ctx->out, crypt(truncpw, salt))` without storing or checking the second `crypt()` result.

`crypt()` is documented to return `NULL` on error. If the second call returns `NULL`, `strcmp()` receives a `NULL` pointer argument.

## Why This Is A Real Bug

The first successful `crypt(pw, salt)` call does not guarantee the later `crypt(truncpw, salt)` call will also succeed. `crypt()` failures can depend on runtime, backend, or resource conditions. Because the second result is unchecked, a valid reachable request path can trigger undefined behavior.

For configurations where Lua exposes `r:htpassword(..., ALG_CRYPT)` to attacker-controlled passwords longer than 8 bytes, the practical impact is denial of service through a worker crash.

## Fix Requirement

Store the result of `crypt(truncpw, salt)` in a temporary variable and verify it is non-`NULL` before passing it to `strcmp()`.

## Patch Rationale

The patch reuses the existing `cbuf` variable for the second `crypt()` result and guards the truncation-warning comparison:

```c
cbuf = crypt(truncpw, salt);
if (cbuf != NULL && !strcmp(ctx->out, cbuf)) {
```

This preserves existing behavior when `crypt()` succeeds and prevents `strcmp()` from receiving a `NULL` argument when it fails. The warning is simply skipped if the second hash cannot be computed.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/lua/lua_passwd.c b/modules/lua/lua_passwd.c
index ad86536..571d10f 100644
--- a/modules/lua/lua_passwd.c
+++ b/modules/lua/lua_passwd.c
@@ -132,7 +132,8 @@ int mk_password_hash(passwd_ctx *ctx)
         if (strlen(pw) > 8) {
             char *truncpw = apr_pstrdup(ctx->pool, pw);
             truncpw[8] = '\0';
-            if (!strcmp(ctx->out, crypt(truncpw, salt))) {
+            cbuf = crypt(truncpw, salt);
+            if (cbuf != NULL && !strcmp(ctx->out, cbuf)) {
                 ctx->errstr = apr_psprintf(ctx->pool,
                                            "Warning: Password truncated to 8 "
                                            "characters by CRYPT algorithm.");
```