# unsupported proxy public key pinning fails open

## Classification

Authentication bypass. Severity: high. Confidence: certain.

## Affected Locations

`src/config2setopts.c:365-371` (`ssl_setopts`, `--proxy-pinnedpubkey` warn-and-continue branch)

## Summary

When `--proxy-pinnedpubkey` is configured but `CURLOPT_PROXY_PINNEDPUBLICKEY` is rejected by libcurl, curl only emits a warning and continues the transfer. The configured proxy public-key pin is therefore not enforced, allowing a CA-valid HTTPS proxy certificate with a different key to be accepted.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- User configures an HTTPS proxy.
- User sets `--proxy-pinnedpubkey`.
- The linked libcurl rejects `CURLOPT_PROXY_PINNEDPUBLICKEY`, for example with `CURLE_NOT_BUILT_IN` or `CURLE_UNKNOWN_OPTION`.
- The proxy presents a CA-valid certificate for the proxy name whose public key does not match the configured pin.

## Proof

`config2setopts` calls `ssl_setopts` for TLS transfers. In `ssl_setopts`, `config->proxy_pinnedpubkey` is applied through:

```c
MY_SETOPT_STR(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
              config->proxy_pinnedpubkey);
```

If that setopt fails, the existing code only warns:

```c
warnf("ignoring %s, not supported by libcurl with %s",
      "--proxy-pinnedpubkey", ssl_backend());
```

Execution then continues and `ssl_setopts` eventually returns `CURLE_OK`.

The reproducer confirmed a practical support mismatch:

- `lib/setopt.c` returns `CURLE_NOT_BUILT_IN` for `CURLOPT_PROXY_PINNEDPUBLICKEY` unless the active TLS backend advertises `SSLSUPP_PINNEDPUBKEY`.
- `lib/vtls/rustls.c` supports HTTPS proxy TLS through `SSLSUPP_HTTPS_PROXY` but does not advertise `SSLSUPP_PINNEDPUBKEY`.
- `MY_SETOPT_STR` treats `CURLE_NOT_BUILT_IN` and `CURLE_UNKNOWN_OPTION` as non-lethal, so the setopt failure does not abort setup.
- The transfer proceeds with normal CA and hostname validation, but without the requested proxy public-key pin.

An attacker-controlled or impersonating HTTPS proxy with a CA-valid unpinned certificate can therefore satisfy normal TLS validation while bypassing the configured proxy pin.

## Why This Is A Real Bug

`--proxy-pinnedpubkey` is an explicit authentication constraint. If curl cannot enforce it, continuing the transfer silently weakens the requested security policy from “CA-valid and pinned proxy key” to only “CA-valid proxy certificate.”

This is fail-open behavior for a security option. The warning does not prevent the connection, and the final result is `CURLE_OK`, so callers and scripts can treat the transfer as successful despite the pin not being applied.

## Fix Requirement

If `CURLOPT_PROXY_PINNEDPUBLICKEY` fails while `--proxy-pinnedpubkey` is configured, curl must abort setup and return the libcurl error instead of continuing without the proxy pin.

## Patch Rationale

The patch changes the failure path for `CURLOPT_PROXY_PINNEDPUBLICKEY` from warning-and-continue to immediate error propagation:

```diff
-      warnf("ignoring %s, not supported by libcurl with %s",
-            "--proxy-pinnedpubkey", ssl_backend());
+      return result;
```

This preserves the user’s security intent. A transfer requiring proxy key pinning now fails closed when the configured pin cannot be enforced.

## Residual Risk

None

## Patch

```diff
diff --git a/src/config2setopts.c b/src/config2setopts.c
index 9138b3b147..0800138817 100644
--- a/src/config2setopts.c
+++ b/src/config2setopts.c
@@ -366,8 +366,7 @@ static CURLcode ssl_setopts(struct OperationConfig *config, CURL *curl)
     MY_SETOPT_STR(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
                   config->proxy_pinnedpubkey);
     if(result)
-      warnf("ignoring %s, not supported by libcurl with %s",
-            "--proxy-pinnedpubkey", ssl_backend());
+      return result;
   }
 
   if(config->ssl_ec_curves)
```