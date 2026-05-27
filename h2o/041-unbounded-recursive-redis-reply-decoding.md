# Unbounded Recursive Redis Reply Decoding

## Classification

Denial of service, low severity. Confidence: certain. Requires malicious or compromised Redis backend reached via mruby Redis API.

## Affected Locations

- `lib/handler/mruby/redis.c:180`
- Function: `decode_redis_reply`

## Summary

`decode_redis_reply` recursively decodes `REDIS_REPLY_ARRAY` values without enforcing a maximum nesting depth. If an application sends Redis commands to an attacker-controlled or compromised Redis-compatible server, that server can return a deeply nested RESP array and exhaust the mruby worker stack, causing process termination.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced with repository hiredis behavior and a local recursive traversal equivalent to H2O’s `decode_redis_reply`.

## Preconditions

- The application issues H2O mruby Redis commands.
- The configured Redis backend is attacker-controlled, malicious, compromised, or otherwise able to return arbitrary RESP replies.

## Proof

The Redis command path is:

1. `call_method` sends an asynchronous Redis command using `h2o_redis_command_argv`.
2. The callback `on_redis_command` receives the parsed `redisReply`.
3. If `errstr == NULL`, `on_redis_command` calls `decode_redis_reply`.
4. For `REDIS_REPLY_ARRAY`, `decode_redis_reply` allocates an mruby array and recursively calls itself for each nested element.
5. No recursion-depth limit is checked before recursing.

Relevant vulnerable behavior:

```c
case REDIS_REPLY_ARRAY:
    decoded = mrb_ary_new_capa(mrb, (mrb_int)reply->elements);
    mrb_int i;
    for (i = 0; i != reply->elements; ++i)
        mrb_ary_set(mrb, decoded, i, decode_redis_reply(mrb, reply->element[i], command));
    break;
```

A malicious Redis server can respond with a payload such as:

```text
*1\r\n*1\r\n*1\r\n...+OK\r\n
```

The reproducer confirmed that hiredis accepts arbitrarily nested multi-bulk replies, consistent with `deps/hiredis/test.c:453-472`, and that recursive traversal of sufficiently deep parsed replies exits with `SIGSEGV` from stack exhaustion.

## Why This Is A Real Bug

The recursive depth is fully controlled by a Redis peer response. Hiredis constructs the nested `redisReply`, and H2O then performs unbounded C recursion while converting it to mruby values. This can exhaust the worker stack before any application-level limit is applied, producing a concrete denial of service.

## Fix Requirement

Enforce a maximum Redis array nesting depth before recursing into nested `REDIS_REPLY_ARRAY` elements. If the limit is exceeded, return a protocol error instead of continuing recursion.

## Patch Rationale

The patch adds `H2O_MRUBY_REDIS_MAX_ARRAY_NESTING` with a limit of `128`, threads a `nesting` counter through `decode_redis_reply`, and rejects replies whose array depth exceeds the limit.

This preserves normal nested Redis array handling while bounding C stack usage for attacker-controlled replies.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/handler/mruby/redis.c b/lib/handler/mruby/redis.c
index e3ee0fa55..68ab8c67b 100644
--- a/lib/handler/mruby/redis.c
+++ b/lib/handler/mruby/redis.c
@@ -167,7 +167,9 @@ static mrb_value disconnect_method(mrb_state *mrb, mrb_value self)
      1) hiredis's pub/sub doesn't accept custom reply
      2) needless memory allocation must happen without using some tricky ways
  */
-static mrb_value decode_redis_reply(mrb_state *mrb, redisReply *reply, mrb_value command)
+#define H2O_MRUBY_REDIS_MAX_ARRAY_NESTING 128
+
+static mrb_value decode_redis_reply(mrb_state *mrb, redisReply *reply, mrb_value command, unsigned nesting)
 {
     mrb_value decoded;
 
@@ -177,10 +179,16 @@ static mrb_value decode_redis_reply(mrb_state *mrb, redisReply *reply, mrb_value
         decoded = mrb_str_new(mrb, reply->str, reply->len);
         break;
     case REDIS_REPLY_ARRAY:
+        if (nesting >= H2O_MRUBY_REDIS_MAX_ARRAY_NESTING)
+            return mrb_exc_new_lit(mrb, get_error_class(mrb, "ProtocolError"), "redis reply array nesting too deep");
         decoded = mrb_ary_new_capa(mrb, (mrb_int)reply->elements);
         mrb_int i;
-        for (i = 0; i != reply->elements; ++i)
-            mrb_ary_set(mrb, decoded, i, decode_redis_reply(mrb, reply->element[i], command));
+        for (i = 0; i != reply->elements; ++i) {
+            mrb_value element = decode_redis_reply(mrb, reply->element[i], command, nesting + 1);
+            if (mrb_obj_is_kind_of(mrb, element, get_error_class(mrb, "ProtocolError")))
+                return element;
+            mrb_ary_set(mrb, decoded, i, element);
+        }
         break;
     case REDIS_REPLY_INTEGER:
         decoded = mrb_fixnum_value((mrb_int)reply->integer);
@@ -210,7 +218,7 @@ static void on_redis_command(redisReply *_reply, void *_ctx, const char *errstr)
     if (errstr == NULL) {
         if (_reply == NULL)
             return;
-        reply = decode_redis_reply(mrb, _reply, ctx->refs.command);
+        reply = decode_redis_reply(mrb, _reply, ctx->refs.command, 0);
     } else {
         struct RClass *error_klass = NULL;
```
