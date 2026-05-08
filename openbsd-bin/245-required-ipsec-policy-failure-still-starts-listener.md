# required IPsec policy failure still starts listener

## Classification

Policy bypass; high severity; confidence certain.

## Affected Locations

`usr.sbin/npppd/l2tp/l2tpd.c:351`

## Summary

When `require_ipsec` is enabled, `l2tpd_listener_start()` attempts to install required IPsec socket policy before registering the UDP listener. If `ipsec_set_policy()` or `setsockopt(IP_IPSEC_POLICY/IP_ESP_TRANS_LEVEL)` fails, the original code only logs the failure and continues. The listener is then registered and accepts L2TP control packets without the required IPsec enforcement.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

`require_ipsec` is enabled and IPsec policy setup fails during listener start.

## Proof

In `l2tpd_listener_start()`, the `require_ipsec` block configures inbound and outbound IPsec policy. The original failure paths for `ipsec_set_policy(L2TPD_IPSEC_POLICY_IN)`, `setsockopt(IP_IPSEC_POLICY(in))`, `ipsec_set_policy(L2TPD_IPSEC_POLICY_OUT)`, `setsockopt(IP_IPSEC_POLICY(out))`, and the `IP_ESP_TRANS_LEVEL` fallback only log errors or warnings.

After those failures, execution continues to assign `_this->sock`, call `event_set()`, call `event_add()`, and return success. The registered `l2tpd_io_event()` handler receives UDP packets and passes them to `l2tp_ctrl_input()`. The reproduced path confirms a remote unauthenticated L2TP client can send cleartext UDP to the listener and have L2TP control input processed despite the configured IPsec requirement.

## Why This Is A Real Bug

`require_ipsec` is a security policy requirement, not an optional optimization. Failing open leaves the UDP L2TP listener reachable without the socket policy that should require ESP transport protection. Because the listener starts successfully and forwards received packets into L2TP control processing, the configured IPsec requirement can be bypassed by a remote unauthenticated client under the stated failure condition.

## Fix Requirement

Treat every required IPsec setup failure as fatal. The listener start operation must abort, close the socket, avoid registering the read event, and return failure.

## Patch Rationale

The patch changes the `require_ipsec` setup block from fail-open to fail-closed. Each IPsec policy construction or installation failure now jumps to the existing `fail` path. The `fail` path closes the socket when allocated and returns failure, preventing `_this->sock` assignment and event registration.

For the `IP_IPSEC_POLICY` path, the patch frees allocated policy buffers before aborting where needed. For the `IP_ESP_TRANS_LEVEL` fallback, the patch aborts on `setsockopt()` failure instead of logging and continuing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/l2tp/l2tpd.c b/usr.sbin/npppd/l2tp/l2tpd.c
index 6931929..09cc12a 100644
--- a/usr.sbin/npppd/l2tp/l2tpd.c
+++ b/usr.sbin/npppd/l2tp/l2tpd.c
@@ -348,24 +348,31 @@ l2tpd_listener_start(l2tpd_listener *_this)
 			l2tpd_log(_l2tpd, LOG_ERR,
 			    "ipsec_set_policy(L2TPD_IPSEC_POLICY_IN) failed "
 			    "at %s(): %s: %m", __func__, ipsec_strerror());
+			goto fail;
 		} else if (setsockopt(sock, lvl, opt, ipsec_policy_in,
 		    ipsec_get_policylen(ipsec_policy_in)) < 0) {
 			l2tpd_log(_l2tpd, LOG_WARNING,
 			    "setsockopt(,,IP_IPSEC_POLICY(in)) failed "
 			    "in %s(): %m", __func__);
+			free(ipsec_policy_in);
+			goto fail;
 		}
 		if ((ipsec_policy_out = ipsec_set_policy(L2TPD_IPSEC_POLICY_OUT,
 		    strlen(L2TPD_IPSEC_POLICY_OUT))) == NULL) {
 			l2tpd_log(_l2tpd, LOG_ERR,
 			    "ipsec_set_policy(L2TPD_IPSEC_POLICY_OUT) failed "
 			    "at %s(): %s: %m", __func__, ipsec_strerror());
+			free(ipsec_policy_in);
+			goto fail;
 		}
-		if (ipsec_policy_out != NULL &&
-		    setsockopt(sock, lvl, opt, ipsec_policy_out,
+		if (setsockopt(sock, lvl, opt, ipsec_policy_out,
 		    ipsec_get_policylen(ipsec_policy_out)) < 0) {
 			l2tpd_log(_l2tpd, LOG_WARNING,
 			    "setsockopt(,,IP_IPSEC_POLICY(out)) failed "
 			    "in %s(): %m", __func__);
+			free(ipsec_policy_in);
+			free(ipsec_policy_out);
+			goto fail;
 		}
 		free(ipsec_policy_in);
 		free(ipsec_policy_out);
@@ -377,6 +384,7 @@ l2tpd_listener_start(l2tpd_listener *_this)
 			l2tpd_log(_l2tpd, LOG_WARNING,
 			    "setsockopt(,,IP{,V6}_ESP_TRANS_LEVEL(out)) failed "
 			    "in %s(): %m", __func__);
+			goto fail;
 		}
 #else
 #error IP_IPSEC_POLICY or IP_ESP_TRANS_LEVEL must be usable.
```