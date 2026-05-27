# Redis Ticket Updater Leaks Non-String Replies in Retry Loop

## Classification

Denial of service, low severity. Requires malicious or compromised Redis backend.

## Affected Locations

- `src/ssl.c:640`
- `src/ssl.c`, function `ticket_redis_update_tickets`
- `src/ssl.c`, function `ticket_redis_updater`

## Summary

When session tickets are configured to use Redis as the ticket store, `ticket_redis_update_tickets` leaks hiredis `redisReply` objects for non-string `GET` replies. If the ticket vector is empty, the function creates and writes a new ticket, returns `retry = 1`, and `ticket_redis_updater` immediately repeats in a tight loop without delay.

A malicious or compromised Redis backend can repeatedly return non-string `GET` replies, causing unbounded reply-object leaks plus CPU and network exhaustion.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Session tickets are enabled.
- `ticket-store` is configured as `redis`.
- The Redis ticket-store backend is malicious, compromised, or otherwise able to return non-string replies to `GET`.

## Proof

In `ticket_redis_update_tickets`:

```c
if ((reply = redisCommand(ctx, "GET %s", key.base)) == NULL) {
    fprintf(stderr, "[lib/ssl.c] %s:redisCommand GET failed:%s\n", __func__, ctx->errstr);
    goto Exit;
}
if (reply->type == REDIS_REPLY_STRING) {
    int r = parse_tickets(&tickets, reply->str, reply->len, errbuf);
    freeReplyObject(reply);
    if (r != 0) {
        fprintf(stderr, "[lib/ssl.c] %s:failed to parse response:%s\n", __func__, errbuf);
        goto Exit;
    }
}
```

Only `REDIS_REPLY_STRING` replies are freed. For any other reply type, the `reply` pointer remains allocated.

With an empty `tickets` vector:

```c
if (update_tickets(&tickets, now) != 0) {
    tickets_serialized = serialize_tickets(&tickets);
    if ((reply = redisCommand(ctx, "SETEX %s %d %s", key.base, conf.lifetime, tickets_serialized.base)) == NULL) {
        fprintf(stderr, "[lib/ssl.c] %s:redisCommand SETEX failed:%s\n", __func__, ctx->errstr);
        goto Exit;
    }
    freeReplyObject(reply);

    retry = 1;
    goto Exit;
}
```

`update_tickets` creates a new ticket when no valid ticket exists, so it returns nonzero. The `SETEX` reply is freed, but the original non-string `GET` reply is overwritten and lost.

The caller retries immediately:

```c
while (ticket_redis_update_tickets(ctx, conf.ticket.vars.redis.key, time(NULL)))
    ;
```

There is no sleep or backoff inside this retry loop.

A malicious Redis server can respond to each `GET` with a non-string reply such as NIL, ERROR, INTEGER, or ARRAY, and respond to `SETEX` successfully. Each iteration leaks the `GET` reply and immediately repeats.

## Why This Is A Real Bug

The Redis backend is external input to the server process. The code trusts reply type handling but fails to release non-string replies. Because the same path also sets `retry = 1`, the leak is amplified by a no-delay loop.

Impact is concrete:

- one hiredis reply object is leaked per iteration;
- crafted aggregate replies can increase per-iteration memory loss;
- the updater burns CPU and network continuously;
- resource exhaustion can degrade or terminate the server.

## Fix Requirement

- Free every successful `GET` reply regardless of reply type.
- Do not request immediate retry when the `GET` reply is non-string.
- Preserve the existing retry behavior for valid string replies that are parsed and then updated.

## Patch Rationale

The patch records whether the `GET` reply was a string:

```c
int retry = 0, get_is_string;
```

It then frees the reply in both cases:

```c
if ((get_is_string = reply->type == REDIS_REPLY_STRING)) {
    ...
    freeReplyObject(reply);
    ...
} else {
    freeReplyObject(reply);
}
```

Finally, it only retries after `SETEX` if the original `GET` reply was a string:

```c
retry = get_is_string;
```

This removes the memory leak and prevents malicious non-string replies from driving the tight retry loop.

## Residual Risk

None

## Patch

```diff
diff --git a/src/ssl.c b/src/ssl.c
index 2499a94cd..45e745232 100644
--- a/src/ssl.c
+++ b/src/ssl.c
@@ -758,20 +758,22 @@ static int ticket_redis_update_tickets(redisContext *ctx, h2o_iovec_t key, time_
     redisReply *reply;
     session_ticket_vector_t tickets = {NULL};
     h2o_iovec_t tickets_serialized = {NULL};
-    int retry = 0;
+    int retry = 0, get_is_string;
     char errbuf[256];
 
     if ((reply = redisCommand(ctx, "GET %s", key.base)) == NULL) {
         fprintf(stderr, "[lib/ssl.c] %s:redisCommand GET failed:%s\n", __func__, ctx->errstr);
         goto Exit;
     }
-    if (reply->type == REDIS_REPLY_STRING) {
+    if ((get_is_string = reply->type == REDIS_REPLY_STRING)) {
         int r = parse_tickets(&tickets, reply->str, reply->len, errbuf);
         freeReplyObject(reply);
         if (r != 0) {
             fprintf(stderr, "[lib/ssl.c] %s:failed to parse response:%s\n", __func__, errbuf);
             goto Exit;
         }
+    } else {
+        freeReplyObject(reply);
     }
     if (tickets.size > 1)
         qsort(tickets.entries, tickets.size, sizeof(tickets.entries[0]), ticket_sort_compare);
@@ -784,7 +786,7 @@ static int ticket_redis_update_tickets(redisContext *ctx, h2o_iovec_t key, time_
         }
         freeReplyObject(reply);
 
-        retry = 1;
+        retry = get_is_string;
         goto Exit;
     }
```