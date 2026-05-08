# Unterminated Set Name Causes Unbounded Read

## Classification

Out-of-bounds read, denial of service.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.sbin/ldomctl/mdstore.c:233`

## Summary

`mdstore_rx_data()` parses mdstore list replies from the peer. For `MDSET_LIST_REQUEST`, it walks the peer-controlled `sets` payload using a payload-length-bounded loop, but then treats each set name as an unbounded C string.

If a list reply contains a set entry without a NUL byte inside the advertised remaining payload, `xstrdup(&mr->sets[len])` and the subsequent `strlen(&mr->sets[len])` scan past the received message buffer. A malicious or compromised LDC mdstore peer can trigger an out-of-bounds read and crash `ldomctl`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with an ASAN harness using the committed `mdstore_rx_data()` logic.

## Preconditions

`ldomctl` receives an mdstore list reply from the peer.

The peer is malicious, compromised, or otherwise able to send a malformed mdstore list reply.

## Proof

For `MDSET_LIST_REQUEST`, the original code iterates over the list payload with:

```c
for (idx = 0, len = 0; len < mr->payload_len - 24; idx++) {
	set = xmalloc(sizeof(*set));
	set->name = xstrdup(&mr->sets[len]);
	...
	len += strlen(&mr->sets[len]) + 1;
}
```

The loop condition limits the starting offset, but neither string operation is constrained to the remaining payload length.

A concrete malformed reply with `payload_len = 28` and four non-NUL set bytes, such as `AAAA`, enters the loop because `len < mr->payload_len - 24`. `xstrdup(&mr->sets[0])` then searches for a NUL byte past those four advertised payload bytes.

Runtime reproduction with ASAN reported `heap-buffer-overflow` in `strdup`, called from `xstrdup`, called by `mdstore_rx_data()` on this malformed list reply.

## Why This Is A Real Bug

The vulnerable data is peer-controlled and reaches `mdstore_rx_data()` through the registered mdstore service reply handler.

The parser relies on C string termination inside a length-delimited protocol payload. A peer can omit the terminator while still satisfying the outer payload length checks. This makes the process read beyond the received message allocation. In practice, ASAN confirms the read crosses the heap buffer boundary and can terminate `ldomctl`.

## Fix Requirement

Before duplicating or measuring a set name, validate that a NUL byte exists within the remaining `sets` payload.

The length used to advance the parser must be derived from that bounded search result, not from an unbounded `strlen()`.

## Patch Rationale

The patch changes the parser to use `memchr()` over exactly the remaining advertised set payload:

```c
end = memchr(&mr->sets[len], '\0', mr->payload_len - 24 - len);
if (end == NULL)
	errx(1, "Unterminated set name");
```

This guarantees that `xstrdup()` is only called after a terminator is known to exist inside the message payload.

The loop condition is also changed from:

```c
len < mr->payload_len - 24
```

to:

```c
len + 24 < mr->payload_len
```

This avoids unsigned underflow when `payload_len` is smaller than the fixed 24-byte list-response tail before `sets`.

Finally, the parser advances with:

```c
len += end - &mr->sets[len] + 1;
```

This reuses the bounded terminator location and removes the second unbounded scan by `strlen()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdstore.c b/usr.sbin/ldomctl/mdstore.c
index 3592fca..9e009cb 100644
--- a/usr.sbin/ldomctl/mdstore.c
+++ b/usr.sbin/ldomctl/mdstore.c
@@ -210,6 +210,7 @@ mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 {
 	struct mdstore_list_resp *mr = data;
 	struct mdstore_set *set;
+	char *end;
 	int idx;
 
 	if (mr->result != MDST_SUCCESS) {
@@ -228,13 +229,17 @@ mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 
 	switch (mdstore_command) {
 	case MDSET_LIST_REQUEST:
-		for (idx = 0, len = 0; len < mr->payload_len - 24; idx++) {
+		for (idx = 0, len = 0; len + 24 < mr->payload_len; idx++) {
+			end = memchr(&mr->sets[len], '\0',
+			    mr->payload_len - 24 - len);
+			if (end == NULL)
+				errx(1, "Unterminated set name");
 			set = xmalloc(sizeof(*set));
 			set->name = xstrdup(&mr->sets[len]);
 			set->booted_set = (idx == mr->booted_set);
 			set->boot_set = (idx == mr->boot_set);
 			TAILQ_INSERT_TAIL(&mdstore_sets, set, link);
-			len += strlen(&mr->sets[len]) + 1;
+			len += end - &mr->sets[len] + 1;
 			if (mdstore_major >= 2)
 				len += sizeof(uint64_t); /* skip timestamp */
 			if (mdstore_major >= 3)
```