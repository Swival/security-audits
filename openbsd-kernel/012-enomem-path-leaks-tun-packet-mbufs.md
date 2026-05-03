# ENOMEM path leaks tun packet mbufs

## Classification

denial of service, medium severity

## Affected Locations

`net/if_tun.c:1006`

## Summary

`tun_dev_write()` allocates a packet-header mbuf with `m_gethdr()`, then may request external cluster storage with `m_clget()` for large user-controlled tun/tap writes. If `m_clget()` fails, the function returns through `put`, which releases only the tun softc reference and does not free the already allocated mbuf. Repeated reachable allocation failures leak mbufs and can exhaust kernel network memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can open and write to a tun or tap device.

## Proof

A local process with a writable tun/tap device can issue large writes to reach `tun_dev_write()`.

The vulnerable flow is:

- `tun_dev_write()` obtains `sc` with `tun_get()`.
- It allocates `m0` using `m_gethdr(M_DONTWAIT, MT_DATA)`.
- For large writes, it calls `m_clget(m, M_DONTWAIT, alen)`.
- If `m_clget()` fails, `m` lacks `M_EXT`; the code sets `error = ENOMEM`.
- The original code jumps to `put`.
- `put` only calls `tun_put(sc)` and returns.
- The existing `drop` path calls `m_freem(m0)`, but the ENOMEM path bypassed it.

`m_clget()` does not free a caller-supplied mbuf when cluster allocation fails. With a non-NULL mbuf argument, its failure path returns without freeing that caller-owned mbuf. Therefore the packet-header mbuf allocated by `m_gethdr()` remains leaked.

The same ownership issue also applies to the later `m_get(M_DONTWAIT, MT_DATA)` failure after `m0` has already been allocated and may have a partially built chain.

## Why This Is A Real Bug

The error path violates mbuf ownership: once `m0` is allocated, every failure before ownership transfer to `tun_input_process()` must free `m0`.

The `put` label only releases the softc reference:

```c
put:
	tun_put(sc);
	return (error);
```

The correct cleanup label is `drop`:

```c
drop:
	m_freem(m0);
put:
	tun_put(sc);
	return (error);
```

Because mbufs and clusters are globally accounted kernel network memory, repeated attacker-controlled large writes that encounter `M_DONTWAIT` allocation failures can leak packet mbufs and contribute to local denial of service.

## Fix Requirement

All ENOMEM exits after `m0` has been allocated must release the packet mbuf chain before returning. This can be done by jumping to `drop` or by explicitly calling `m_freem(m0)` before the shared `put` path.

## Patch Rationale

The patch changes the two ENOMEM exits that occur after `m0` allocation to use the existing `drop` cleanup path.

This preserves the existing control-flow structure and uses the function’s established mbuf cleanup mechanism:

- Failed `m_clget()` now frees `m0`.
- Failed chained `m_get()` now frees the partially built mbuf chain rooted at `m0`.
- The `put` path remains reserved for exits where no packet mbuf has been allocated.

## Residual Risk

None

## Patch

```diff
diff --git a/net/if_tun.c b/net/if_tun.c
index 2dcdda1..8d4df34 100644
--- a/net/if_tun.c
+++ b/net/if_tun.c
@@ -1009,7 +1009,7 @@ tun_dev_write(dev_t dev, struct uio *uio, int ioflag, int align)
 			m_clget(m, M_DONTWAIT, alen);
 			if (!ISSET(m->m_flags, M_EXT)) {
 				error = ENOMEM;
-				goto put;
+				goto drop;
 			}
 		}
 
@@ -1031,7 +1031,7 @@ tun_dev_write(dev_t dev, struct uio *uio, int ioflag, int align)
 		n = m_get(M_DONTWAIT, MT_DATA);
 		if (n == NULL) {
 			error = ENOMEM;
-			goto put;
+			goto drop;
 		}
 
 		align = 0;
```