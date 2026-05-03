# YubiKey Counter Check Updates Non-Atomically

## Classification

Authentication bypass, high severity.

## Affected Locations

- `login_yubikey/login_yubikey.c:221`

## Summary

`yubikey_login()` read the stored YubiKey counter from `/var/db/yubikey/<user>.ctr`, closed the file, validated the submitted OTP, compared the OTP counter against the stale local value, and later reopened the file for writing. Because the read, comparison, and update were not protected by a lock or atomic compare-and-update, concurrent authentication attempts using the same valid OTP could both pass the replay check and both return `AUTH_OK`.

## Provenance

Detected by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The account has YubiKey state files under `/var/db/yubikey`.
- The authentication path accepts concurrent attempts for the same user.
- An attacker possesses one valid YubiKey OTP for that account.

## Proof

The reproducer confirmed the race:

- `main()` accepts the SSH/login response path and passes the supplied response to `yubikey_login()` at `login_yubikey/login_yubikey.c:160`.
- `yubikey_login()` reads `/var/db/yubikey/<user>.ctr` into `last_ctr` and closes it at `login_yubikey/login_yubikey.c:223`.
- The replay check compares `ctr <= last_ctr` at `login_yubikey/login_yubikey.c:283`.
- The counter is later rewritten with `fopen(fn, "w")` and `fprintf()` at `login_yubikey/login_yubikey.c:291`.
- No `flock`, `lockf`, `fcntl`, atomic rename/compare, or open-file lock covered the read/check/write sequence.

Two concurrent helper instances submitting the same valid OTP can both read the old `last_ctr`, both compute the same OTP `ctr`, both observe `ctr > last_ctr`, both write the same counter value, and both return `AUTH_OK` at `login_yubikey/login_yubikey.c:298`.

## Why This Is A Real Bug

YubiKey OTP counters are intended to prevent replay. The security invariant is that accepting an OTP must atomically advance the stored counter before another authentication attempt can make the same decision. The original implementation split that invariant across separate file operations without synchronization, allowing a time-of-check/time-of-use race. Under concurrent SSH authentication, one OTP can authenticate multiple sessions, violating one-time semantics.

## Fix Requirement

Lock the per-user counter file across the complete read, comparison, and update sequence so only one authentication process can evaluate and advance the counter at a time.

## Patch Rationale

The patch moves the counter read to the point where the counter file is opened for update and protects the whole critical section with an exclusive `flock()`:

- Adds `#include <sys/file.h>` for `flock()`.
- Extends `pledge()` with `flock` so the login helper may acquire file locks.
- Opens the counter file with `fopen(fn, "a+")`, allowing creation if missing and read/write access if present.
- Acquires `LOCK_EX` before reading `last_ctr`.
- Performs `ctr <= last_ctr` while the lock is held.
- Rewinds, truncates, and writes the new counter while the same lock is held.
- Returns failure on lock or write errors instead of authenticating without persisting the replay state.

This preserves the existing counter-file storage model while making the replay check and counter update atomic with respect to other cooperating authentication processes.

## Residual Risk

None

## Patch

```diff
diff --git a/login_yubikey/login_yubikey.c b/login_yubikey/login_yubikey.c
index 9fddc61..19d5b7a 100644
--- a/login_yubikey/login_yubikey.c
+++ b/login_yubikey/login_yubikey.c
@@ -30,6 +30,7 @@
  *
  */
 
+#include <sys/file.h>
 #include <sys/stat.h>
 #include <sys/time.h>
 #include <sys/resource.h>
@@ -72,7 +73,7 @@ main(int argc, char *argv[])
 
 	setpriority(PRIO_PROCESS, 0, 0);
 
-	if (pledge("stdio tty wpath rpath cpath", NULL) == -1) {
+	if (pledge("stdio tty wpath rpath cpath flock", NULL) == -1) {
 		syslog(LOG_AUTH|LOG_ERR, "pledge: %m");
 		exit(EXIT_FAILURE);
 	}
@@ -221,11 +222,6 @@ yubikey_login(const char *username, const char *password)
 	}
 
 	snprintf(fn, sizeof(fn), "%s/%s.ctr", path, username);
-	if ((f = fopen(fn, "r")) != NULL) {
-		if (fscanf(f, "%u", &last_ctr) != 1)
-			last_ctr = 0;
-		fclose(f);
-	}
 
 	yubikey_hex_decode(uid, hexuid, YUBIKEY_UID_SIZE);
 	yubikey_hex_decode(key, hexkey, YUBIKEY_KEY_SIZE);
@@ -281,18 +277,32 @@ yubikey_login(const char *username, const char *password)
 	    "%d crc ok", username, mapok, i, crcok);
 
 	ctr = ((u_int32_t)yubikey_counter(tok.ctr) << 8) | tok.use;
-	if (ctr <= last_ctr) {
-		syslog(LOG_INFO, "user %s: counter <= last (REPLAY ATTACK!)",
-		    username);
-		return (AUTH_FAILED);
-	}
-	syslog(LOG_INFO, "user %s: counter > last [OK]", username);
 	umask(S_IRWXO);
-	if ((f = fopen(fn, "w")) == NULL) {
+	if ((f = fopen(fn, "a+")) == NULL) {
 		syslog(LOG_ERR, "user %s: fopen: %s: %m", username, fn);
 		return (AUTH_FAILED);
 	}
-	fprintf(f, "%u", ctr);
+	if (flock(fileno(f), LOCK_EX) == -1) {
+		syslog(LOG_ERR, "user %s: flock: %s: %m", username, fn);
+		fclose(f);
+		return (AUTH_FAILED);
+	}
+	rewind(f);
+	if (fscanf(f, "%u", &last_ctr) != 1)
+		last_ctr = 0;
+	if (ctr <= last_ctr) {
+		syslog(LOG_INFO, "user %s: counter <= last (REPLAY ATTACK!)",
+		    username);
+		fclose(f);
+		return (AUTH_FAILED);
+	}
+	syslog(LOG_INFO, "user %s: counter > last [OK]", username);
+	rewind(f);
+	if (ftruncate(fileno(f), 0) == -1 || fprintf(f, "%u", ctr) < 0) {
+		syslog(LOG_ERR, "user %s: write: %s: %m", username, fn);
+		fclose(f);
+		return (AUTH_FAILED);
+	}
 	fclose(f);
 
 	return (AUTH_OK);
```