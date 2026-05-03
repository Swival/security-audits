# msgrcv copyout ignores truncated receive length

## Classification

High severity out-of-bounds write.

## Affected Locations

`kern/sysv_msg.c:637`

## Summary

`sys_msgrcv` passes the receiver-supplied `msgsz` by pointer to `msg_copyout`. `msg_copyout` correctly computes a truncated transfer length with `xfer = min(*len, msg->msg_len)` and reports that value through `*len`, but the copyout loop ignores `xfer` and copies every mbuf at its full `m->m_len`. A sender that queues a message larger than the receiver's buffer can cause attacker-controlled message bytes to be copied past the requested receive payload.

## Provenance

Verified and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- A local sender has write access to a SysV message queue that the victim reads.
- The sender queues a message whose payload length exceeds the victim's `msgsz`.
- The receiver calls `msgrcv` with a destination buffer sized for `sizeof(long) + msgsz`.

## Proof

- `sys_msgrcv` locates a queued message and calls `msg_copyout(msg, msgp, &msgsz, p)` before dequeueing it.
- `msg_copyout` computes `xfer = min(*len, msg->msg_len)`, so the intended payload copy length is the smaller receiver-provided size.
- `msg_copyout` then writes `*len = xfer`, so the syscall return value reports the truncated length.
- The mbuf loop copies `m->m_len` for every mbuf in `msg->msg_data`, not the remaining `xfer`.
- Therefore, when `msg->msg_len > msgsz`, the kernel copies `msg->msg_len - msgsz` additional attacker-controlled bytes beyond the requested receive buffer.
- If the overrun lands in mapped writable memory, `copyout` can succeed and `sys_msgrcv` returns the truncated length, masking the overwrite; if it reaches unmapped memory, the attacker can trigger an `EFAULT` failure path.

## Why This Is A Real Bug

The function already establishes truncation semantics by calculating `xfer` and returning that value through `*len`. The subsequent copy loop violates that bound by using each mbuf's full length and iterating over the full stored message. This creates a direct mismatch between the length reported to the caller and the number of bytes actually written to user memory.

## Fix Requirement

Limit the payload copyout loop to the remaining truncated transfer length across mbufs. Each iteration must copy at most `min(remaining, m->m_len)` and stop once the remaining length reaches zero.

## Patch Rationale

The patch preserves the existing truncation behavior and syscall return semantics while enforcing the computed transfer bound during copyout. It introduces a per-mbuf `mlen` capped by the remaining `xfer`, advances the user pointer by the actual copied amount, decrements `xfer`, and stops once the truncated payload length has been copied.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/sysv_msg.c b/kern/sysv_msg.c
index fe07031..92dbfac 100644
--- a/kern/sysv_msg.c
+++ b/kern/sysv_msg.c
@@ -618,7 +618,7 @@ int
 msg_copyout(struct msg *msg, char *ubuf, size_t *len, struct proc *p)
 {
 	struct mbuf *m;
-	size_t xfer;
+	size_t xfer, mlen;
 	int error;
 
 #ifdef DIAGNOSTIC
@@ -635,10 +635,12 @@ msg_copyout(struct msg *msg, char *ubuf, size_t *len, struct proc *p)
 	ubuf += sizeof(long);
 	*len = xfer;
 
-	for (m = msg->msg_data; m; m = m->m_next) {
-		if ((error = copyout(mtod(m, void *), ubuf, m->m_len)))
+	for (m = msg->msg_data; m && xfer > 0; m = m->m_next) {
+		mlen = min(xfer, m->m_len);
+		if ((error = copyout(mtod(m, void *), ubuf, mlen)))
 			return (error);
-		ubuf += m->m_len;
+		ubuf += mlen;
+		xfer -= mlen;
 	}
 
 	return (0);
```