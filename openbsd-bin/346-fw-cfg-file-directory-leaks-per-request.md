# FW_CFG file directory leaks per request

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`usr.sbin/vmd/fw_cfg.c:401`

## Summary

A guest-controlled `FW_CFG_FILE_DIR` selector request causes `vmd` to allocate a temporary fw_cfg file directory buffer and never release it. Repeating the selector request leaks host process memory until `vmd` exhausts memory or terminates.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced by source inspection of the selector dispatch, directory allocation, and state-copy ownership behavior.

## Preconditions

- A guest can access the fw_cfg selector interface.
- The guest can repeatedly write selector `FW_CFG_FILE_DIR` to `FW_CFG_IO_SELECT`, or trigger equivalent DMA select handling.

## Proof

The guest-controlled path is:

- `vcpu_exit_fw_cfg()` handles writes to `FW_CFG_IO_SELECT` and calls `fw_cfg_select(data)`.
- `fw_cfg_handle_dma()` also calls `fw_cfg_select(selector)` when `FW_CFG_DMA_SELECT` is set.
- `fw_cfg_select()` resets only the prior `fw_cfg_state.data`, then dispatches selector `FW_CFG_FILE_DIR` to `fw_cfg_file_dir()`.
- `fw_cfg_file_dir()` computes `size = sizeof(count) + count * sizeof(struct fw_cfg_file)`.
- `fw_cfg_file_dir()` allocates `data = malloc(size)`.
- `fw_cfg_file_dir()` passes `data` to `fw_cfg_set_state(data, size)`.
- `fw_cfg_set_state()` allocates a separate `fw_cfg_state.data` buffer and copies the supplied input with `memcpy()`.
- `fw_cfg_set_state()` does not take ownership of the caller's `data`.
- `fw_cfg_file_dir()` returned without freeing `data`.

Therefore, each `FW_CFG_FILE_DIR` selection leaked one directory buffer of `sizeof(count) + count * sizeof(struct fw_cfg_file)` bytes in the host `vmd` process.

## Why This Is A Real Bug

The allocation in `fw_cfg_file_dir()` is not the same allocation later stored in `fw_cfg_state.data`. The state setter performs a deep copy, so the original temporary directory buffer remains owned by `fw_cfg_file_dir()` and must be freed there.

Because the selector is guest-controlled and can be requested repeatedly, the leak is externally triggerable from a malicious VM guest. The leak accumulates in the long-lived host `vmd` process and can cause memory exhaustion, allocation failures, or process termination.

## Fix Requirement

Release the temporary directory buffer after `fw_cfg_set_state(data, size)` returns, or change `fw_cfg_set_state()` ownership semantics so it takes ownership of the caller-provided allocation.

The minimal safe fix is to free `data` in `fw_cfg_file_dir()` after the state copy.

## Patch Rationale

The patch adds `free(data)` immediately after `fw_cfg_set_state(data, size)`.

This is correct because:

- `fw_cfg_set_state()` copies the buffer contents into newly allocated `fw_cfg_state.data`.
- The copied state remains valid after the caller frees the temporary source buffer.
- The temporary buffer has no further uses after `fw_cfg_set_state()` returns.
- Existing state lifetime behavior is unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/fw_cfg.c b/usr.sbin/vmd/fw_cfg.c
index 3d096f9..04661f3 100644
--- a/usr.sbin/vmd/fw_cfg.c
+++ b/usr.sbin/vmd/fw_cfg.c
@@ -400,4 +400,5 @@ fw_cfg_file_dir(void)
 	/* XXX should sort by name but SeaBIOS does not care */
 
 	fw_cfg_set_state(data, size);
+	free(data);
 }
```