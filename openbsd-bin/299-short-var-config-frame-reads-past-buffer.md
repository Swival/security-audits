# short var-config frame reads past buffer

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/ldomd/var-config.c:127`

## Summary

`var_config_rx_data()` casts attacker-controlled DS payload data to `struct var_config_set_req *` and reads `vr->cmd` before verifying that the received frame is long enough to contain the `cmd` field. A short `DS_DATA` frame can therefore make `ldomd` read beyond the received var-config buffer during request dispatch.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can send var-config DS data to `ldomd`.

## Proof

`ldomd` registers the `var-config` DS service for non-primary guests. Incoming LDC data is accepted with an attacker-controlled length and passed through DS dispatch to the registered service.

The reproduced path is:

- `ldomd` opens `/dev/ldom-<guest>` and registers `var-config` at `usr.sbin/ldomd/ldomd.c:201`.
- `ldc_rx_data()` passes assembled message data and `lc_len` to `ds_rx_msg()` at `usr.sbin/ldomd/ds.c:270`.
- `ds_rx_msg()` dispatches `DS_DATA` by `svc_handle` without validating service payload length at `usr.sbin/ldomd/ds.c:482`.
- `var_config_rx_data()` reads `vr->cmd` at `usr.sbin/ldomd/var-config.c:127` before any length check.

A 16-byte `DS_DATA` frame containing only `msg_type`, `payload_len`, and `svc_handle` reaches `var_config_rx_data()`. The `cmd` field is at offset 16 and requires at least 20 bytes to read, so dispatch reads outside the received var-config frame.

## Why This Is A Real Bug

The vulnerable code dereferences a packed request structure without first proving that `len` covers the accessed member:

```c
struct var_config_set_req *vr = data;

switch (vr->cmd) {
```

Because `cmd` follows `msg_type`, `payload_len`, and `svc_handle`, a frame shorter than `offsetof(struct var_config_set_req, name)` does not contain the complete `cmd` field. The reproduced 16-byte frame reaches this code path and causes an out-of-bounds read from `ldomd` memory.

## Fix Requirement

Reject frames shorter than `offsetof(struct var_config_set_req, name)` before reading `vr->cmd`.

## Patch Rationale

The patch includes `<stddef.h>` for `offsetof()` and adds a minimum-length guard before the first access to `vr->cmd`.

`offsetof(struct var_config_set_req, name)` is the first byte after `cmd`, so this check proves that the fixed-size request header through `cmd` is present before dispatch. Frames that cannot contain the command are ignored, preventing the out-of-bounds read.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomd/var-config.c b/usr.sbin/ldomd/var-config.c
index b3cabb0..a8b4858 100644
--- a/usr.sbin/ldomd/var-config.c
+++ b/usr.sbin/ldomd/var-config.c
@@ -22,6 +22,7 @@
 #include <assert.h>
 #include <err.h>
 #include <fcntl.h>
+#include <stddef.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -125,6 +126,9 @@ var_config_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
 	struct var_config_set_req *vr = data;
 	struct var_config_resp vx;
 
+	if (len < offsetof(struct var_config_set_req, name))
+		return;
+
 	switch (vr->cmd) {
 	case VAR_CONFIG_SET_REQ:
 		vx.msg_type = DS_DATA;
```