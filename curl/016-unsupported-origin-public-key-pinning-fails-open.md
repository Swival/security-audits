# Unsupported Origin Public Key Pinning Fails Open

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`src/config2setopts.c:359-364` (`ssl_setopts`, `--pinnedpubkey` warn-and-continue branch)

## Summary

`--pinnedpubkey` is a security control for origin TLS public key pinning. When `CURLOPT_PINNEDPUBLICKEY` cannot be set, `ssl_setopts` only emits a warning and continues. If normal CA and hostname verification succeed, the transfer proceeds without enforcing the requested public key pin.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The user supplies `--pinnedpubkey`.
- libcurl rejects `CURLOPT_PINNEDPUBLICKEY`, for example with `CURLE_NOT_BUILT_IN`.
- Normal TLS CA and hostname verification succeeds.
- The peer certificate public key does not match the requested pin.

## Proof

In `ssl_setopts`, when `config->pinnedpubkey` is set, the code calls:

```c
MY_SETOPT_STR(curl, CURLOPT_PINNEDPUBLICKEY, config->pinnedpubkey);
```

If that call fails, the affected code only warns:

```c
warnf("ignoring %s, not supported by libcurl with %s",
      "--pinnedpubkey", ssl_backend());
```

The function later returns `CURLE_OK`, so `config2setopts` continues and `curl_easy_perform` is reached. With a Rustls-backed build where the pin option is rejected, a malicious TLS server with a CA-valid but unpinned certificate can be accepted.

The documented invariant is that `--pinnedpubkey` causes curl to extract the peer public key and abort before sending or receiving data if it does not match. The reproduced behavior violates that invariant because the pin is never installed and no equivalent fallback pin check is performed.

## Why This Is A Real Bug

Public key pinning is an explicit origin authentication control. A warning is insufficient because the transfer still succeeds under a weaker trust model than the user requested. The user asked curl to require a specific public key, but the tool silently downgrades enforcement to ordinary CA validation, allowing a CA-valid unpinned endpoint to be accepted.

## Fix Requirement

If `CURLOPT_PINNEDPUBLICKEY` cannot be set for an origin pin, curl must fail setup and abort the transfer instead of continuing without the pin check.

## Patch Rationale

The patch changes the error handling for origin `--pinnedpubkey` from fail-open to fail-closed. When `MY_SETOPT_STR` reports an error, `ssl_setopts` now returns that `CURLcode` immediately. `config2setopts` already checks `setopt_bad(result)` after `ssl_setopts`, so the existing caller path stops the transfer before network operation proceeds.

## Residual Risk

None

## Patch

```diff
diff --git a/src/config2setopts.c b/src/config2setopts.c
index 9138b3b147..cdd802fdea 100644
--- a/src/config2setopts.c
+++ b/src/config2setopts.c
@@ -359,8 +359,7 @@ static CURLcode ssl_setopts(struct OperationConfig *config, CURL *curl)
   if(config->pinnedpubkey) {
     MY_SETOPT_STR(curl, CURLOPT_PINNEDPUBLICKEY, config->pinnedpubkey);
     if(result)
-      warnf("ignoring %s, not supported by libcurl with %s",
-            "--pinnedpubkey", ssl_backend());
+      return result;
   }
   if(config->proxy_pinnedpubkey) {
     MY_SETOPT_STR(curl, CURLOPT_PROXY_PINNEDPUBLICKEY,
```