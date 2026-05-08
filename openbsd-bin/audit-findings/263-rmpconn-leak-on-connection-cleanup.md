# RMPCONN leak on connection cleanup

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/rbootd/utils.c:388`

## Summary

`FreeConn()` intends to keep one freed `RMPCONN` in the `LastFree` cache and free subsequent connections. The empty-cache branch assigns in the wrong direction:

```c
rtmp = LastFree;
```

Because `LastFree` is initially `NULL`, this drops the only pointer to the connection being cleaned up. The connection is neither cached nor freed, causing one `RMPCONN` heap leak per cleanup. Repeated accepted RMP connection creation and removal from local-network clients can exhaust daemon memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The daemon accepts RMP connection state from local network clients.
- A remote RMP client on the local network can send accepted packets that create and later remove `RMPCONN` objects.

## Proof

`NewConn()` allocates an `RMPCONN` with `malloc(sizeof(RMPCONN))` when `LastFree == NULL`.

`RemoveConn()` and `FreeConns()` dispose connections through `FreeConn()`.

In `FreeConn()`, the intended empty-cache behavior is to retain the just-freed connection for reuse:

```c
if (LastFree == NULL)        /* cache for next time */
        rtmp = LastFree;
else
        free((char *)rtmp);
```

This assignment is reversed. Since `LastFree` starts as `NULL`, `rtmp` becomes `NULL` and the original allocated object is lost without being freed. `LastFree` remains `NULL`, so the next cleanup repeats the leak.

The reproduced network path is:

- `RMP_BOOT_REQ` calls `NewConn()` in `usr.sbin/rbootd/rmpproto.c:86`.
- Probe or denied boot-request paths call `FreeConn()` in `usr.sbin/rbootd/rmpproto.c:110` and `usr.sbin/rbootd/rmpproto.c:116`.
- Active connection cleanup also reaches `FreeConn()` via duplicate boot requests in `usr.sbin/rbootd/rmpproto.c:288`, boot completion in `usr.sbin/rbootd/rmpproto.c:534`, or timeout cleanup in `usr.sbin/rbootd/rbootd.c:285`.

A practical trigger is repeated accepted `RMP_BOOT_REQ` probe packets with session `RMP_PROBESID`. Each packet allocates approximately one `RMPCONN` and then leaks it. No cap or rate limit was identified in this path.

## Why This Is A Real Bug

The code comment says the object should be cached when `LastFree == NULL`, but the implementation overwrites the only live pointer with `NULL`. The allocated object is no longer reachable from `RmpConns`, `LastFree`, or the local variable. `FreeConns()` cannot recover it later because the leaked object is neither linked nor cached.

This is reachable from normal packet processing by local-network RMP clients and can be repeated until daemon memory is exhausted, causing denial of service.

## Fix Requirement

When the cache is empty, store the connection in `LastFree`:

```c
LastFree = rtmp;
```

When the cache is already occupied, free the connection normally.

## Patch Rationale

The patch corrects the assignment direction in the empty-cache branch. This restores the intended one-entry cache behavior documented directly above `LastFree` and in the `FreeConn()` comment:

- First cleaned-up connection is retained in `LastFree`.
- Next `NewConn()` reuses `LastFree`.
- Additional cleaned-up connections are freed when the cache is already occupied.
- `FreeConns()` can free the cached object during full cleanup.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rbootd/utils.c b/usr.sbin/rbootd/utils.c
index dc38cc1..b4a32ae 100644
--- a/usr.sbin/rbootd/utils.c
+++ b/usr.sbin/rbootd/utils.c
@@ -391,7 +391,7 @@ FreeConn(RMPCONN *rtmp)
 	}
 
 	if (LastFree == NULL)		/* cache for next time */
-		rtmp = LastFree;
+		LastFree = rtmp;
 	else				/* already one cached; free this one */
 		free((char *)rtmp);
 }
```