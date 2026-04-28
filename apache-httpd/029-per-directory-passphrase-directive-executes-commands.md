# Per-Directory Passphrase Directive Executes Commands

## Classification

Trust-boundary violation. Severity: medium. Confidence: certain.

## Affected Locations

`modules/session/mod_session_crypto.c:771`

## Summary

`SessionCryptoPassphrase` was allowed in per-directory override context via `OR_AUTHCFG`. The same directive handler treats values beginning with `exec:` as a command, tokenizes the command line, resolves the executable path, and calls `ap_get_exec_line`. Therefore, an attacker who can write `.htaccess` in a directory where `AllowOverride AuthConfig` is enabled can cause local command execution during configuration processing.

## Provenance

Verified from the supplied source, reproduced from the described control flow, and patched as shown.

Source: Swival Security Scanner, https://swival.dev

## Preconditions

- `mod_session_crypto` is loaded.
- An administrator enables `AllowOverride AuthConfig` for a directory.
- The directory is writable by an attacker who can create or modify `.htaccess`.
- A request or configuration path causes that per-directory override file to be parsed.

## Proof

`SessionCryptoPassphrase` is registered with:

```c
AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG, ...)
```

Because `OR_AUTHCFG` permits the directive in `.htaccess`, untrusted per-directory configuration can reach `set_crypto_passphrase`.

In `set_crypto_passphrase`, values beginning with `exec:` are handled specially:

```c
if ((arglen > 5) && strncmp(arg, "exec:", 5) == 0) {
    apr_tokenize_to_argv(arg+5, &argv, cmd->temp_pool);
    argv[0] = ap_server_root_relative(cmd->temp_pool, argv[0]);
    result = ap_get_exec_line(cmd->pool,
                              (const char*)argv[0],
                              (const char * const *)argv);
    *passphrase = result;
}
```

A writable `.htaccess` can therefore contain:

```apache
SessionCryptoPassphrase "exec:/path/to/local/program arg1 arg2"
```

When directory override parsing processes that file, the directive handler executes the local program as the web server user. The command output is used as the session crypto passphrase, but execution has already occurred.

## Why This Is A Real Bug

This crosses a trust boundary between delegated directory configuration and server-side command execution. `AllowOverride AuthConfig` is commonly used to delegate authentication-related configuration to directory owners, but it should not grant those owners a path to run arbitrary local programs.

The behavior is not mere variable expansion or delayed interpretation. The handler calls `ap_get_exec_line`, and the reproduced path confirms `ap_get_exec_line` creates a process via `apr_proc_create`. This is actual command execution during config processing.

## Fix Requirement

`SessionCryptoPassphrase` must not be accepted from `.htaccess` or other untrusted per-directory override contexts while it supports the `exec:` command form.

The directive should be restricted to server configuration unless command execution is explicitly disabled for override contexts.

## Patch Rationale

The patch removes `OR_AUTHCFG` from the `SessionCryptoPassphrase` directive registration:

```diff
-    AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG,
+    AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF,
```

This prevents `.htaccess` from invoking `set_crypto_passphrase`, while preserving the existing `exec:` behavior for trusted server configuration. It closes the privilege boundary violation without changing passphrase parsing semantics for administrators.

## Residual Risk

None

## Patch

`029-per-directory-passphrase-directive-executes-commands.patch`

```diff
diff --git a/modules/session/mod_session_crypto.c b/modules/session/mod_session_crypto.c
index fe39f2c..9fb17ba 100644
--- a/modules/session/mod_session_crypto.c
+++ b/modules/session/mod_session_crypto.c
@@ -775,7 +775,7 @@ static const char *set_crypto_cipher(cmd_parms * cmd, void *config, const char *
 
 static const command_rec session_crypto_cmds[] =
 {
-    AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF|OR_AUTHCFG,
+    AP_INIT_ITERATE("SessionCryptoPassphrase", set_crypto_passphrase, NULL, RSRC_CONF,
             "The passphrase(s) used to encrypt the session. First will be used for encryption, all phrases will be accepted for decryption"),
     AP_INIT_TAKE1("SessionCryptoPassphraseFile", set_crypto_passphrase_file, NULL, RSRC_CONF|ACCESS_CONF,
             "File containing passphrase(s) used to encrypt the session, one per line. First will be used for encryption, all phrases will be accepted for decryption"),
```