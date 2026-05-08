# GETBULK non-repeater offset writes past varbind array

## Classification

High severity out-of-bounds write.

## Affected Locations

- `lib/libagentx/agentx.c:1168`
- `lib/libagentx/agentx.c:2615`
- `lib/libagentx/agentx.c:2616`
- `lib/libagentx/agentx.c:2625`
- `lib/libagentx/agentx.c:2626`
- `lib/libagentx/agentx.c:2663`

## Summary

A malicious AgentX master can send a crafted `GETBULK` request that causes the subagent to compute a repeated-varbind index past the heap array allocated for GETBULK processing. The bug is in `agentx_get_start()`: the repeated search range offset uses the absolute search range index `i` instead of the repeater-relative index `i - axg_nonrep`.

## Provenance

Reported and verified from Swival Security Scanner output: https://swival.dev

Confidence: certain.

## Preconditions

- A subagent is connected to an attacker-controlled AgentX master.
- The attacker can negotiate or use a valid AgentX session/context.
- The attacker sends a `GETBULK` PDU with controlled `nonrep`, `maxrep`, and search ranges.

## Proof

For a `GETBULK` request with:

- `ap_nsr = 2`
- `nonrep = 1`
- `maxrep = 2`
- two search ranges

`agentx_get_start()` computes:

```c
axg->axg_nvarbind = ((srl->ap_nsr - axg->axg_nonrep) *
    axg->axg_maxrep) + axg->axg_nonrep;
```

This yields:

```text
((2 - 1) * 2) + 1 == 3
```

So `calloc()` allocates three `agentx_varbind` elements, valid indices `0..2`.

During initialization, the loop reaches `i = 1`. Since this is not a non-repeater and `maxrep != 0`, the vulnerable code computes:

```c
j = (axg->axg_maxrep * i) + axg->axg_nonrep;
```

This yields:

```text
(2 * 1) + 1 == 3
```

The following writes then target `axg->axg_varbind[3]`, one element past the allocated array:

```c
bcopy(&(srl->ap_sr[i].asr_start),
    &(axg->axg_varbind[j].axv_vb.avb_oid),
    sizeof(srl->ap_sr[i].asr_start));
```

Additional scalar assignments also write through the same out-of-bounds element.

## Why This Is A Real Bug

The allocation size and index calculation disagree. `axg_nvarbind` correctly accounts for non-repeaters by allocating:

```text
nonrep + ((ap_nsr - nonrep) * maxrep)
```

But the repeated-varbind initialization uses:

```text
(maxrep * i) + nonrep
```

where `i` includes the non-repeater offset. For any `nonrep > 0`, this skips too far into the repeated section. With the reproduced values, the first repeated search range immediately indexes one past the allocation.

The attacker-controlled AgentX master can provide the triggering `GETBULK` PDU to the connected subagent, making the heap overwrite reachable through normal protocol dispatch from `agentx_read()` to `agentx_get_start()`.

## Fix Requirement

- Compute the repeated GETBULK output index relative to the first repeater: `i - axg_nonrep`.
- Reject or abort malformed computations if the resulting index is outside `axg_nvarbind`.
- Apply the same corrected index calculation in both initialization loops in `agentx_get_start()`.

## Patch Rationale

The patch changes the repeated-varbind index from:

```c
j = (axg->axg_maxrep * i) + axg->axg_nonrep;
```

to:

```c
j = (axg->axg_maxrep * (i - axg->axg_nonrep)) +
    axg->axg_nonrep;
```

This aligns the index with the allocation formula by making the repeated portion zero-based after the non-repeater prefix.

The added `j >= axg->axg_nvarbind` checks provide a defensive bounds guard before any write or `agentx_varbind_start()` access. On failure, the code logs the parse failure, frees request state, resets the AgentX connection, and returns.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libagentx/agentx.c b/lib/libagentx/agentx.c
index eba2add..963f30d 100644
--- a/lib/libagentx/agentx.c
+++ b/lib/libagentx/agentx.c
@@ -2612,7 +2612,15 @@ agentx_get_start(struct agentx_context *axc, struct ax_pdu *pdu)
 		else if (axg->axg_maxrep == 0)
 			break;
 		else
-			j = (axg->axg_maxrep * i) + axg->axg_nonrep;
+			j = (axg->axg_maxrep * (i - axg->axg_nonrep)) +
+			    axg->axg_nonrep;
+		if (j >= axg->axg_nvarbind) {
+			agentx_log_axg_warn(axg, "Couldn't parse request");
+			free(logmsg);
+			agentx_get_free(axg);
+			agentx_reset(ax);
+			return;
+		}
 		bcopy(&(srl->ap_sr[i].asr_start),
 		    &(axg->axg_varbind[j].axv_vb.avb_oid),
 		    sizeof(srl->ap_sr[i].asr_start));
@@ -2660,7 +2668,14 @@ agentx_get_start(struct agentx_context *axc, struct ax_pdu *pdu)
 		else if (axg->axg_maxrep == 0)
 			break;
 		else
-			j = (axg->axg_maxrep * i) + axg->axg_nonrep;
+			j = (axg->axg_maxrep * (i - axg->axg_nonrep)) +
+			    axg->axg_nonrep;
+		if (j >= axg->axg_nvarbind) {
+			agentx_log_axg_warn(axg, "Couldn't parse request");
+			agentx_get_free(axg);
+			agentx_reset(ax);
+			return;
+		}
 		agentx_varbind_start(&(axg->axg_varbind[j]));
 	}
 }
```