# Claude API key prefix written to attacker-readable temp log

## Classification

Information disclosure, low severity.

Confidence: certain.

This script is a developer-facing diagnostic, not part of the sandbox runtime. nono is normally deployed on single-user developer workstations, where the "lower-privileged local user" attacker is not part of the operative threat model. The bug is still worth fixing because the script is shipped in the repository and the disclosure is gratuitous, but the practical risk on the intended deployment is limited.

## Affected Locations

`scripts/monitor-auth.sh:36`

## Summary

`scripts/monitor-auth.sh` logged the first 20 characters of a Claude API key to a fixed file in `/tmp`. Because `/tmp` is shared and the log path was predictable, a lower-privileged local user could precreate an attacker-readable log file and observe the victim monitor append credential material.

## Provenance

Verified and patched finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim has a Claude API key in one of the monitored JSON files.
- Victim runs `scripts/monitor-auth.sh`.
- Attacker is a lower-privileged local user on the same host.
- Attacker can precreate `/tmp/nono-auth-monitor.log` as readable/writable before the victim runs the monitor.

## Proof

The vulnerable script set a fixed shared-temp log path:

```bash
LOG="/tmp/nono-auth-monitor.log"
```

The logging function appended through `tee` without enforcing private ownership or permissions:

```bash
echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
```

`check_file` extracted `.apiKey` or `.api_key` from monitored Claude credential/settings JSON and truncated it to 20 bytes:

```bash
key_prefix=$(jq -r '.apiKey // .api_key // empty' "$path" 2>/dev/null | head -c 20 || true)
```

It then wrote the truncated secret to the log:

```bash
[ -n "$key_prefix" ] && log "    key_prefix=${key_prefix}..."
```

A lower-privileged local attacker could precreate `/tmp/nono-auth-monitor.log`, for example as an attacker-owned readable/writable file. When the victim ran the monitor, `tee -a "$LOG"` appended `key_prefix=...` into that attacker-readable file, disclosing the first 20 characters of the victim's Claude API key.

## Why This Is A Real Bug

The disclosed value is credential material. Even though only a prefix was logged, API key prefixes can aid secret identification, correlation, phishing, debugging artifact abuse, or partial credential exposure analysis.

The bug is practical because the log path is fixed, located in shared `/tmp`, and written without ownership or permission checks. The attacker does not need to control the victim's environment or the credential file; they only need local access to precreate the predictable log file.

## Fix Requirement

The script must not write secret material to logs. If logging remains necessary, it must only record non-sensitive state such as whether an API key exists.

A private `0600` log path would reduce the shared-temp exposure, but it would not address the broader issue that credential material was being logged. The required fix is to stop logging the key prefix.

## Patch Rationale

The patch replaces logging of the API key prefix with a boolean presence indicator:

```diff
-            [ -n "$key_prefix" ] && log "    key_prefix=${key_prefix}..."
+            [ -n "$key_prefix" ] && log "    has_api_key=yes"
```

This preserves the diagnostic purpose of confirming that a key exists while removing credential material from log output. With no key prefix emitted, precreating `/tmp/nono-auth-monitor.log` no longer yields the Claude API key prefix.

## Residual Risk

None

## Patch

```diff
diff --git a/scripts/monitor-auth.sh b/scripts/monitor-auth.sh
index fda0e86..bfb6ca8 100755
--- a/scripts/monitor-auth.sh
+++ b/scripts/monitor-auth.sh
@@ -33,7 +33,7 @@ check_file() {
             has_refresh=$(jq -r 'if .refreshToken // .refresh_token then "yes" else "no" end' "$path" 2>/dev/null || true)
 
             [ -n "$key_source" ] && log "    apiKeySource=$key_source"
-            [ -n "$key_prefix" ] && log "    key_prefix=${key_prefix}..."
+            [ -n "$key_prefix" ] && log "    has_api_key=yes"
             [ -n "$expires_at" ] && log "    expires_at=$expires_at"
             [ "$has_refresh" = "yes" ] && log "    has_refresh_token=yes"
         fi
```