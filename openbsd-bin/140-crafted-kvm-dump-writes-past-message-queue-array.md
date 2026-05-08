# Crafted KVM Dump Writes Past Message Queue Array

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/ipcs/ipcs.c:722`

## Summary

`ipcs -C` trusts message queue indices read from a supplied kvm core file. A crafted queue node can set `msgque.que_ix` outside the bounds of the heap-allocated `msqids` array, causing `ipcs_kvm()` to write a full `struct msqid_ds` past the allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim runs `ipcs -C attacker_core` with message info enabled. Message info is enabled by default or explicitly with `-q`.

## Proof

`-C` sets `core`, and `main()` calls `ipcs_kvm()` when `core` or `namelist` is set.

In `ipcs_kvm()`:

- `msginfo` is read from the kvm image.
- `msqids` is allocated for exactly `msginfo.msgmni` entries.
- `_msg_queues` is read from the kvm image.
- The message queue TAILQ is walked by repeatedly reading attacker-controlled queue nodes with `kvm_read()`.
- Each node's `msgque.que_ix` is used directly as an array index:
  `msqids[msgque.que_ix] = msgque.msqid_ds`.

A crafted dump with `msginfo.msgmni = 1`, one readable fake queue node, `msgque.que_ix = 1`, and `TAILQ_NEXT(...)=0` writes one `struct msqid_ds` beyond the allocated heap array. Larger indices can trigger attacker-controlled heap corruption or process crash in the victim `ipcs` process.

## Why This Is A Real Bug

The kvm core file is an untrusted input in this execution mode. `msginfo.msgmni` defines the allocated array length, but `msgque.que_ix` comes from separately read queue nodes and was not checked before indexing. Therefore the write is not constrained to the allocation bounds.

## Fix Requirement

Validate `msgque.que_ix` before assignment. The index must be nonnegative and strictly less than `msginfo.msgmni`.

## Patch Rationale

The patch adds the missing lower and upper bound checks around the only write using `msgque.que_ix`. Invalid queue nodes are ignored, preserving processing of well-formed queues while preventing heap writes outside `msqids`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ipcs/ipcs.c b/usr.bin/ipcs/ipcs.c
index 95196d9..436adb1 100644
--- a/usr.bin/ipcs/ipcs.c
+++ b/usr.bin/ipcs/ipcs.c
@@ -724,7 +724,9 @@ ipcs_kvm(void)
 				    != sizeof(msgque))
 					errx(1, "kvm_read (%s): %s",
 					    "msg que", kvm_geterr(kd));
-				msqids[msgque.que_ix] = msgque.msqid_ds;
+				if (msgque.que_ix >= 0 &&
+				    msgque.que_ix < msginfo.msgmni)
+					msqids[msgque.que_ix] = msgque.msqid_ds;
 				addr = (u_long)TAILQ_NEXT(&msgque, que_next);
 			}
```