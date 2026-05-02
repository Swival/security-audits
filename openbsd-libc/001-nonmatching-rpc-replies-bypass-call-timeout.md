# Nonmatching RPC Replies Bypass Call Timeout

## Classification

Denial of service, medium severity.

## Affected Locations

`rpc/clnt_tcp.c:272`

## Summary

A TCP RPC client call can remain blocked indefinitely when connected to an attacker-controlled server that continuously sends syntactically valid RPC reply records with nonmatching transaction IDs.

`clnttcp_call()` waits in an unbounded receive loop until it decodes a reply whose `rm_xid` matches the current call XID. `readtcp()` only enforced `ct_wait` per individual read/poll operation, so each attacker-supplied nonmatching reply refreshed the timeout window. This bypassed the intended call timeout and allowed a malicious server to keep the client stuck.

## Provenance

Verified from supplied source, reproducer analysis, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Client makes a TCP RPC call to an attacker-controlled server.
- Server can observe or infer the request framing enough to send valid RPC reply records.
- Server sends replies before each per-read timeout expires.

## Proof

`clnttcp_call()` sends the request and then enters a `while (TRUE)` receive loop:

- `xdrrec_skiprecord(xdrs)` advances to the next record.
- `xdr_replymsg(xdrs, &reply_msg)` decodes the reply header.
- Decode failures with no recorded RPC error continue the loop.
- Replies with `reply_msg.rm_xid != x_id` fall through and repeat.
- The loop only breaks when `reply_msg.rm_xid == x_id`.

`readtcp()` previously initialized a fresh `delta = wait` for each read operation, where `wait` came from `ct->ct_wait`. It returned `RPC_TIMEDOUT` only if that individual `ppoll()` expired. If the attacker sent another valid nonmatching reply before each poll timeout, `readtcp()` returned data and the outer loop continued with a new per-read timeout.

A malicious TCP RPC server can therefore repeatedly send well-formed RPC reply records with any nonmatching XID. Authentication validation is not reached until after the XID match, so these records are sufficient to keep the client in the receive loop.

Result: the client RPC call remains blocked indefinitely instead of timing out.

## Why This Is A Real Bug

The configured RPC call timeout is expected to bound the duration of a call. In the affected implementation, it only bounded each individual socket wait. Because the outer receive loop had no absolute deadline or elapsed-time check, attacker-controlled progress on the socket prevented timeout forever.

This is externally triggerable by a malicious RPC server and causes denial of service in any client thread or process waiting for the call to return.

## Fix Requirement

Enforce an absolute deadline for the whole receive phase of a TCP RPC call, not a fresh timeout per `readtcp()` invocation.

Each read must compute its remaining timeout from the call-level deadline and return `RPC_TIMEDOUT` once that deadline has passed, even if previous reads received nonmatching records.

## Patch Rationale

The patch adds `ct_deadline` to `struct ct_data` and sets it in `clnttcp_call()` immediately before entering the reply receive loop:

- Converts `ct_wait` to a `struct timespec`.
- Reads the current monotonic time.
- Stores `now + wait` as `ct->ct_deadline`.

`readtcp()` then computes `delta` as `ct_deadline - now` before each `ppoll()`:

- If the remaining time is negative or zero, it returns `RPC_TIMEDOUT`.
- Otherwise, it polls only for the remaining call-level duration.
- EINTR handling recomputes the remaining time instead of restarting with a full timeout.

This preserves normal successful reads while preventing nonmatching replies from refreshing the timeout budget.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/clnt_tcp.c b/rpc/clnt_tcp.c
index 86675f8..6ab1b3c 100644
--- a/rpc/clnt_tcp.c
+++ b/rpc/clnt_tcp.c
@@ -82,6 +82,7 @@ struct ct_data {
 	bool_t		ct_closeit;
 	int		ct_connected;	/* pre-connected */
 	struct timeval	ct_wait;
+	struct timespec	ct_deadline;
 	bool_t          ct_waitset;       /* wait set by clnt_control? */
 	struct sockaddr_in ct_addr; 
 	struct rpc_err	ct_error;
@@ -230,6 +231,7 @@ clnttcp_call(CLIENT *h, u_long proc, xdrproc_t xdr_args, caddr_t args_ptr,
 	struct ct_data *ct = (struct ct_data *) h->cl_private;
 	XDR *xdrs = &(ct->ct_xdrs);
 	struct rpc_msg reply_msg;
+	struct timespec now, wait;
 	u_long x_id;
 	u_int32_t *msg_x_id = (u_int32_t *)(ct->ct_mcall);	/* yuk */
 	bool_t shipnow;
@@ -267,6 +269,9 @@ call_again:
 		return(ct->ct_error.re_status = RPC_TIMEDOUT);
 	}
 
+	TIMEVAL_TO_TIMESPEC(&ct->ct_wait, &wait);
+	WRAP(clock_gettime)(CLOCK_MONOTONIC, &now);
+	timespecadd(&now, &wait, &ct->ct_deadline);
 
 	/*
 	 * Keep receiving until we get a valid transaction id
@@ -387,7 +392,7 @@ static int
 readtcp(struct ct_data *ct, caddr_t buf, int len)
 {
 	struct pollfd pfd[1];
-	struct timespec start, after, duration, delta, wait;
+	struct timespec now, delta;
 	int r, save_errno;
 
 	if (len == 0)
@@ -395,19 +400,17 @@ readtcp(struct ct_data *ct, caddr_t buf, int len)
 
 	pfd[0].fd = ct->ct_sock;
 	pfd[0].events = POLLIN;
-	TIMEVAL_TO_TIMESPEC(&ct->ct_wait, &wait);
-	delta = wait;
-	WRAP(clock_gettime)(CLOCK_MONOTONIC, &start);
 	for (;;) {
+		WRAP(clock_gettime)(CLOCK_MONOTONIC, &now);
+		timespecsub(&ct->ct_deadline, &now, &delta);
+		if (delta.tv_sec < 0 || !timespecisset(&delta)) {
+			ct->ct_error.re_status = RPC_TIMEDOUT;
+			return (-1);
+		}
+
 		r = ppoll(pfd, 1, &delta, NULL);
 		save_errno = errno;
 
-		WRAP(clock_gettime)(CLOCK_MONOTONIC, &after);
-		timespecsub(&start, &after, &duration);
-		timespecsub(&wait, &duration, &delta);
-		if (delta.tv_sec < 0 || !timespecisset(&delta))
-			r = 0;
-
 		switch (r) {
 		case 0:
 			ct->ct_error.re_status = RPC_TIMEDOUT;
```