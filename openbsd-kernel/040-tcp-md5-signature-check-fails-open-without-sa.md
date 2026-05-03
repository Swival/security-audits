# TCP MD5 signature check fails open without SA

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`netinet/tcp_input.c:1588`

`netinet/tcp_input.c:2262`

`netinet/tcp_input.c:2269`

`netinet/tcp_input.c:2274`

`netinet/tcp_input.c:3817`

`netinet/tcp_input.c:3821`

`netinet/tcp_input.c:3958`

## Summary

A TCP listener configured with `TCP_SIGNATURE` can accept an unsigned remote SYN when no matching TCP MD5 Security Association exists for the peer. The TCP MD5 verifier clears the required-signature flag in LISTEN state on missing SA, causing the later signature-required check to treat the unsigned packet as acceptable.

The patch removes the fail-open flag clearing so missing SA no longer disables `TF_SIGNATURE`.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

The finding was reproduced by tracing `syn_cache_add()` and `tcp_dooptions()` behavior for an unsigned SYN against a `TCP_SIGNATURE` listener with no peer SA.

## Preconditions

- Kernel built with `TCP_SIGNATURE`.
- Listening socket has `TCP_SIGNATURE` enabled.
- Remote client has no matching TCP MD5 SA.
- Remote client sends an unsigned SYN to the listening socket.

## Proof

`syn_cache_add()` copies the listener's `TF_SIGNATURE` into local `tb`, sets `tb.t_state = TCPS_LISTEN`, and calls `tcp_dooptions()`.

Inside `tcp_dooptions()`, `gettdbbysrcdst()` returns `NULL` when no SA exists for the source/destination pair. Because the temporary TCP control block is in `TCPS_LISTEN`, the old code cleared `TF_SIGNATURE`.

For an unsigned SYN, `sigp == NULL`. After `TF_SIGNATURE` is cleared, this check does not reject the packet:

```c
if ((sigp ? TF_SIGNATURE : 0) ^ (tp->t_flags & TF_SIGNATURE)) {
	tcpstat_inc(tcps_rcvbadsig);
	goto bad;
}
```

Because `tcp_dooptions()` returns success and `tb.t_flags` no longer contains `TF_SIGNATURE`, `syn_cache_add()` does not set `SCF_SIGNATURE`. The SYN cache entry is inserted without signature enforcement, and `syn_cache_get()` later creates an accepted connection without `TF_SIGNATURE`.

Impact: a remote client without the TCP MD5 key/SA can complete an accepted TCP connection to a TCP MD5-enabled listener.

## Why This Is A Real Bug

`TCP_SIGNATURE` is an authentication control. A listener with `TF_SIGNATURE` requires TCP MD5 validation for inbound connection establishment. Missing SA means the verifier cannot authenticate the segment; it must reject the segment, not silently disable the requirement.

The old LISTEN-state special case converts an unverifiable unsigned SYN into an accepted SYN by mutating `tp->t_flags`. That directly bypasses the configured security control and persists into SYN cache state by omitting `SCF_SIGNATURE`.

## Fix Requirement

Do not clear `TF_SIGNATURE` when no SA is found. If `TF_SIGNATURE` is required:

- unsigned segments must fail the signature-presence check;
- signed segments without a matching SA must fail the later `tdb == NULL` check;
- only correctly signed segments with a matching SA may proceed.

## Patch Rationale

The patch deletes only the LISTEN-state fail-open behavior:

```diff
-		/*
-		 * We don't have an SA for this peer, so we turn off
-		 * TF_SIGNATURE on the listen socket
-		 */
-		if (tdb == NULL && tp->t_state == TCPS_LISTEN)
-			tp->t_flags &= ~TF_SIGNATURE;
```

With this removed, `TF_SIGNATURE` remains set on the temporary LISTEN-state control block used by `syn_cache_add()`.

For unsigned SYNs, `sigp == NULL` while `TF_SIGNATURE` remains set, so the XOR check rejects the segment.

For signed SYNs without SA, `sigp != NULL` and `TF_SIGNATURE` remains set, so the XOR check passes, but the later `tdb == NULL` check rejects the segment.

For valid signed SYNs with SA, behavior is preserved.

## Residual Risk

None

## Patch

`004-tcp-md5-signature-check-fails-open-without-sa.patch`

```diff
diff --git a/netinet/tcp_input.c b/netinet/tcp_input.c
index c2e6211..10955ff 100644
--- a/netinet/tcp_input.c
+++ b/netinet/tcp_input.c
@@ -2262,13 +2262,6 @@ tcp_dooptions(struct tcpcb *tp, u_char *cp, int cnt, struct tcphdr *th,
 		tdb = gettdbbysrcdst(rtable_l2(rtableid),
 		    0, &src, &dst, IPPROTO_TCP);
 
-		/*
-		 * We don't have an SA for this peer, so we turn off
-		 * TF_SIGNATURE on the listen socket
-		 */
-		if (tdb == NULL && tp->t_state == TCPS_LISTEN)
-			tp->t_flags &= ~TF_SIGNATURE;
-
 	}
 
 	if ((sigp ? TF_SIGNATURE : 0) ^ (tp->t_flags & TF_SIGNATURE)) {
```