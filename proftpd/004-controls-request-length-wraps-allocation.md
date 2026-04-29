# controls request length wraps allocation

## Classification

High severity out-of-bounds heap write.

## Affected Locations

`src/ctrls.c:530`

## Summary

`pr_ctrls_recv_request()` reads an attacker-controlled 32-bit request length from a local controls socket and uses it to allocate `msglen + 1` bytes before reading `msglen` bytes into that buffer. Large values can overflow or otherwise underallocate through the pool allocator path, causing heap memory to be overwritten.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The controls socket accepts a client and calls `pr_ctrls_recv_request()`.

## Proof

A lower-privileged local controls client can send a malicious request length prefix.

The vulnerable path is:

- `pr_ctrls_recv_request()` reads `msglen` from `cl->cl_fd` into a `uint32_t`.
- It allocates the request buffer with `pcalloc(tmp_pool, msglen + 1)`.
- It then reads `msglen` bytes from the socket into that buffer.
- For a crafted large length such as `0xfffffffe`, `msglen + 1` becomes `0xffffffff`.
- The pool allocator rounds that size to `0x100000000`, then passes it through `new_block(int minsz)`, truncating through the `int` parameter.
- On normal 64-bit builds this underallocates a small pool block.
- `pcalloc()` then zeroes `0xffffffff` bytes via `memset(res, '\0', sz)`, causing an out-of-bounds heap write before the socket body is read.

The reachable call path is through `mod_ctrls`: accepted clients are added to `cl_list`, and `ctrls_cls_read()` calls `pr_ctrls_recv_request()`.

## Why This Is A Real Bug

The request length is fully attacker-controlled and is trusted before allocation. The code performs arithmetic on that untrusted length and passes the result into allocator internals that cannot safely represent the resulting size on the observed path. The same untrusted length is also used as the socket read size. This creates a concrete heap out-of-bounds write reachable from a local controls client.

The original `0xffffffff` proof text is not the exact practical trigger on the reproduced build, but the reproduced `0xfffffffe` trigger confirms the same bug class and impact.

## Fix Requirement

Reject request lengths above a sane maximum before adding one byte for NUL termination or allocating the request buffer.

## Patch Rationale

The patch adds an explicit upper-bound check immediately after the fixed-size length prefix is read and before `msglen + 1` is evaluated:

```c
if (msglen > PR_TUNABLE_CMD_BUFFER_SIZE) {
  pr_trace_msg(trace_channel, 3,
    "request message size %lu exceeds maximum %lu bytes",
    (unsigned long) msglen, (unsigned long) PR_TUNABLE_CMD_BUFFER_SIZE);
  pr_signals_unblock();
  errno = EINVAL;
  return -1;
}
```

This prevents oversized attacker-controlled lengths from reaching the allocation and read logic. Using `PR_TUNABLE_CMD_BUFFER_SIZE` provides an existing bounded command-size policy rather than allowing arbitrary 32-bit request bodies.

## Residual Risk

None

## Patch

`004-controls-request-length-wraps-allocation.patch`

```diff
diff --git a/src/ctrls.c b/src/ctrls.c
index 5f23bda42..85c1af78f 100644
--- a/src/ctrls.c
+++ b/src/ctrls.c
@@ -631,6 +631,15 @@ int pr_ctrls_recv_request(pr_ctrls_cl_t *cl) {
     return -1;
   }
 
+  if (msglen > PR_TUNABLE_CMD_BUFFER_SIZE) {
+    pr_trace_msg(trace_channel, 3,
+      "request message size %lu exceeds maximum %lu bytes",
+      (unsigned long) msglen, (unsigned long) PR_TUNABLE_CMD_BUFFER_SIZE);
+    pr_signals_unblock();
+    errno = EINVAL;
+    return -1;
+  }
+
   tmp_pool = make_sub_pool(cl->cl_pool);
   pr_pool_tag(tmp_pool, "Controls API recv_request pool");
```