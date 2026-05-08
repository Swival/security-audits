# Short mdstore Reply Reads Past Packet

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/ldomctl/mdstore.c:215`

## Summary

`mdstore_rx_data()` casts attacker-supplied packet bytes to `struct mdstore_list_resp *` and reads `mr->result` before verifying that the received `len` includes the `result` field. A short mdstore reply can therefore read past the packet boundary and terminate `ldomctl`.

## Provenance

Verified and reproduced from the supplied finding. Scanner provenance: [Swival Security Scanner](https://swival.dev).

## Preconditions

`ldomctl` receives mdstore data from an attacker-controlled LDC mdstore peer.

## Proof

`mdstore_rx_data()` receives untrusted `data` and `len`, then immediately treats `data` as a `struct mdstore_list_resp *`.

The `result` field begins at offset 24:

- `msg_type`: 4 bytes
- `payload_len`: 4 bytes
- `svc_handle`: 8 bytes
- `reqnum`: 8 bytes
- `result`: next 4 bytes

A crafted 24-byte `DS_DATA` mdstore reply reaches `mdstore_rx_data()` without containing `result`. The function still evaluates `mr->result`, causing a packet-boundary out-of-bounds/stale read.

The reproducer confirms deterministic termination by first registering `mdstore` with a normal `DS_REG_REQ` and chosen handle, leaving nonzero service-id bytes in the reused receive buffer at offset 24, then sending a one-fragment 24-byte `DS_DATA` reply with the same handle. `mdstore_rx_data()` reads the stale bytes as a non-success result and exits via `errx()`.

## Why This Is A Real Bug

The packet length is attacker-controlled input metadata and must bound all field accesses. The vulnerable code dereferences `mr->result` before any length check, so a syntactically short packet can cause a read beyond the supplied mdstore reply. Because the read value controls an `errx()` path, a malicious peer can terminate `ldomctl`, producing a denial of service.

## Fix Requirement

Validate that `len` covers the fixed header through `result` before casting or dereferencing response fields.

## Patch Rationale

The patch delays assigning `data` to `struct mdstore_list_resp *mr` until after a minimum length check. It requires at least 28 bytes, which covers the packet fields through the 4-byte `result` member at offset 24. Shorter messages are rejected with `errx(1, "Short mdstore message")` before any out-of-bounds read can occur.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdstore.c b/usr.sbin/ldomctl/mdstore.c
index 3592fca..febbd51 100644
--- a/usr.sbin/ldomctl/mdstore.c
+++ b/usr.sbin/ldomctl/mdstore.c
@@ -208,10 +208,14 @@ void
 mdstore_rx_data(struct ldc_conn *lc, uint64_t svc_handle, void *data,
     size_t len)
 {
-	struct mdstore_list_resp *mr = data;
+	struct mdstore_list_resp *mr;
 	struct mdstore_set *set;
 	int idx;
 
+	if (len < 28)
+		errx(1, "Short mdstore message");
+
+	mr = data;
 	if (mr->result != MDST_SUCCESS) {
 		switch (mr->result) {
 		case MDST_SET_EXISTS_ERR:
```