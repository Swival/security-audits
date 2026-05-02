# Ignored Realloc Failure Enables Oversized Body Read

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`rpc/xdr_rec.c:538`

## Summary

`__xdrrec_getrec()` accepts a peer-controlled nonblocking RPC record fragment whose length is larger than the current receive buffer but within `in_maxrec`. It then calls `realloc_stream()` to grow the input buffer, but ignores allocation failure. If `realloc()` fails, the buffer remains at the smaller `recvsize`, yet execution continues to read `in_reclen` bytes into it, allowing a remote peer to trigger a heap out-of-bounds write.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer analysis.

## Preconditions

- Nonblocking XDR record mode is enabled.
- `in_maxrec` is larger than the current `recvsize`.
- A remote RPC peer sends a fragment length greater than `recvsize` but not greater than `in_maxrec`.
- `realloc_stream(rstrm, rstrm->in_reclen)` fails.

## Proof

`__xdrrec_getrec()` parses the remote-controlled record header and computes:

```c
fraglen = (int)(rstrm->in_header & ~LAST_FRAG);
```

The fragment is accepted when:

```c
fraglen <= rstrm->in_maxrec
(rstrm->in_reclen + fraglen) <= rstrm->in_maxrec
```

The accepted length is accumulated:

```c
rstrm->in_reclen += fraglen;
```

When the record length exceeds the current receive buffer, the vulnerable code calls `realloc_stream()` but ignores its return value:

```c
if (rstrm->in_reclen > rstrm->recvsize)
	realloc_stream(rstrm, rstrm->in_reclen);
```

On allocation failure, `realloc_stream()` returns `FALSE` without changing `in_base`, `recvsize`, or `in_boundry`:

```c
buf = realloc(rstrm->in_base, size);
if (buf == NULL)
	return (FALSE);
```

Execution then continues to read the oversized body into the unchanged smaller buffer:

```c
n = rstrm->readit(rstrm->tcp_handle,
    rstrm->in_base + rstrm->in_received,
    (rstrm->in_reclen - rstrm->in_received));
```

Because `in_base` still points to the original `recvsize` allocation from `xdrrec_create()`, the read callback can write past the heap buffer.

## Why This Is A Real Bug

The allocation result directly controls whether the destination buffer is large enough for the subsequent read. The code validates the attacker-controlled length against `in_maxrec`, not against the actual allocated buffer size. If growth fails, the actual allocation remains smaller than `in_reclen`, but the code still passes `in_reclen - in_received` as the read size.

This is reachable by a remote RPC peer on a nonblocking TCP connection and can cause remote denial of service or heap corruption under memory pressure or resource limits.

## Fix Requirement

If `realloc_stream()` fails while growing the nonblocking input buffer, `__xdrrec_getrec()` must stop processing, set `*statp = XPRT_DIED`, and return `FALSE` before calling `readit()`.

## Patch Rationale

The patch converts the unchecked resize into a checked failure path. When `in_reclen` exceeds `recvsize`, the code now requires `realloc_stream()` to succeed before continuing. On failure, the transport is marked dead and no body read occurs into the undersized buffer.

This preserves the existing behavior for successful allocations and rejects only the unsafe allocation-failure case.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/xdr_rec.c b/rpc/xdr_rec.c
index b3445d5..05b04eb 100644
--- a/rpc/xdr_rec.c
+++ b/rpc/xdr_rec.c
@@ -541,8 +541,11 @@ __xdrrec_getrec(XDR *xdrs, enum xprt_stat *statp, bool_t expectdata)
 			return (FALSE);
 		}
 		rstrm->in_reclen += fraglen;
-		if (rstrm->in_reclen > rstrm->recvsize)
-			realloc_stream(rstrm, rstrm->in_reclen);
+		if (rstrm->in_reclen > rstrm->recvsize &&
+		    !realloc_stream(rstrm, rstrm->in_reclen)) {
+			*statp = XPRT_DIED;
+			return (FALSE);
+		}
 		if (rstrm->in_header & LAST_FRAG) {
 			rstrm->in_header &= ~LAST_FRAG;
 			rstrm->last_frag = TRUE;
```