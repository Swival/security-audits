# Indirect BPF word load wraps packet offset

## Classification

High severity denial of service.

Confidence: certain.

## Affected Locations

`net/bpf_filter.c:81`

## Summary

`bpf_mem_ldw()` validates packet bounds with `k + sizeof(v) > bm->len`. On 32-bit offset arithmetic, an attacker-controlled indirect BPF word load can make `k` near `UINT_MAX`, causing the addition to wrap below `bm->len`. The check then passes and `memcpy()` reads outside the packet buffer, which can crash the kernel.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

The kernel accepts an attacker-supplied BPF filter containing `BPF_LD|BPF_W|BPF_IND`.

A local process is allowed to install or trigger BPF filters.

## Proof

A valid trigger program is:

```text
LDX IMM 0xfffffffc
LD W IND 0
RET K ...
```

Execution path:

- `_bpf_filter()` loads `0xfffffffc` into `X` via `BPF_LDX|BPF_IMM`.
- `_bpf_filter()` handles `BPF_LD|BPF_W|BPF_IND` by computing `k = X + pc->k`.
- With `pc->k == 0`, `k == 0xfffffffc`.
- `bpf_mem_ldw()` checks `k + sizeof(v) > bm->len`.
- On 32-bit arithmetic, `0xfffffffc + 4` wraps to `0`.
- For a small `bm->len`, the wrapped value does not exceed the packet length, so `err` is cleared.
- `memcpy(&v, bm->pkt + k, sizeof(v))` then reads four bytes outside the packet buffer.

The contiguous-buffer path is reachable because `bpfwrite()` calls `bpf_movein()`, and `bpf_movein()` applies the write filter through `bpf_filter()`, which uses `bpf_mem_ldw()`.

## Why This Is A Real Bug

`bpf_validate()` permits `BPF_IND` when `pc->k` is below `bpf_maxbufsize`, but it does not constrain the runtime value of `X`.

The runtime check in `bpf_mem_ldw()` relies on an addition that can overflow before comparison. Therefore, a validated BPF program can bypass the bounds check and force an out-of-packet kernel read. If the resulting address faults, the kernel may panic; if it is mapped, the BPF program can branch on data outside the packet.

## Fix Requirement

Reject the access before performing an overflowing addition.

The bounds check must ensure:

- the packet is at least the word size; and
- `k` is no greater than `bm->len - sizeof(v)`.

## Patch Rationale

The patch changes the word-load bounds check from an overflow-prone addition to subtraction after verifying the packet length is large enough:

```c
if (bm->len < sizeof(v) || k > bm->len - sizeof(v))
	return (0);
```

This preserves valid reads where the complete word is inside the packet and fails closed for short packets or offsets too large to contain a full word.

## Residual Risk

None

## Patch

```diff
diff --git a/net/bpf_filter.c b/net/bpf_filter.c
index 005a57a..ff03f01 100644
--- a/net/bpf_filter.c
+++ b/net/bpf_filter.c
@@ -78,7 +78,7 @@ bpf_mem_ldw(const void *mem, u_int32_t k, int *err)
 
 	*err = 1;
 
-	if (k + sizeof(v) > bm->len)
+	if (bm->len < sizeof(v) || k > bm->len - sizeof(v))
 		return (0);
 
 	memcpy(&v, bm->pkt + k, sizeof(v));
```