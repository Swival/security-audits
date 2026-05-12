# devhub PAT exposed in git clone argv

## Classification

Information disclosure, low severity. Confidence: certain.

The `devhub` job runs on a GitHub-hosted `ubuntu-22.04` runner (`.github/workflows/ci.yml:144`), which is ephemeral and single-tenant, so there is no concurrent unprivileged local user able to observe `/proc/<pid>/cmdline`. The practical exposure is therefore limited to incidental leakage paths (logs that dump argv, third-party tools that capture process commands, future migrations to self-hosted or shared runners). Tightening this is still defense in depth and matches GitHub's own credential-handling guidance.

## Affected Locations

`src/scripts/devhub.zig:402`

## Summary

`upload_run` embedded `DEVHUBDB_PAT` directly into the `git clone` remote URL. Because `Shell.exec` expands the command into process argv and spawns `git` directly, the PAT became visible to local users able to inspect process arguments on a shared CI runner.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

`metrics upload` runs with `DEVHUBDB_PAT` set on any machine where another local user, a log collector, or another tool can observe the `git clone` process arguments. Today this is the GitHub-hosted runner; the risk grows the moment a self-hosted runner, container with sidecars, or external observability agent enters the picture.

## Proof

`upload_run` reads `DEVHUBDB_PAT` and used it in:

```zig
https://oauth2:{token}@github.com/tigerbeetle/devhubdb.git
```

The command is executed through `Shell.exec`, which expands the command into argv and spawns it with `std.process.Child.init(argv, ...)`. Therefore the resulting `git clone` process arguments contained the full PAT-bearing URL.

The token documentation states the PAT has `Contents` read/write permission for `tigerbeetle/devhubdb`, and the same repository is later pushed to with `git push`. Disclosure therefore enables unauthorized writes to the devhubdb repository.

## Why This Is A Real Bug

Process arguments are commonly observable by local users through facilities such as `/proc` or process listing tools, depending on runner isolation and OS policy. Under the stated shared CI runner precondition, exposing a write-capable PAT in argv creates a concrete credential disclosure path.

## Fix Requirement

Pass the GitHub credential through a channel that does not place the secret in process argv. The clone URL must not contain `DEVHUBDB_PAT`.

## Patch Rationale

The patch removes the token from the remote URL and clones from:

```text
https://github.com/tigerbeetle/devhubdb.git
```

When `DEVHUBDB_PAT` is present, it supplies a Git credential helper through `--config`:

```text
credential.helper=!f() { printf '%s\n' username=oauth2 password="$DEVHUBDB_PAT"; }; f
```

The argv now contains only the literal environment variable reference, not the PAT value. Git obtains the password from the environment inside the credential helper, avoiding direct token disclosure in the `git clone` argv.

## Residual Risk

None

## Patch

```diff
diff --git a/src/scripts/devhub.zig b/src/scripts/devhub.zig
index 9628afaa1..d7ef55240 100644
--- a/src/scripts/devhub.zig
+++ b/src/scripts/devhub.zig
@@ -397,12 +397,17 @@ fn get_measurement(
 
 fn upload_run(shell: *Shell, batch: *const MetricBatch) !void {
     const token = shell.env_get_option("DEVHUBDB_PAT");
+    const credential_config: []const []const u8 = if (token == null) &.{} else &.{
+        "--config",
+        "credential.helper=!f() { printf '%s\\n' username=oauth2 password=\"$DEVHUBDB_PAT\"; }; f",
+    };
     try shell.exec(
         \\git clone --single-branch --depth 1
-        \\  https://oauth2:{token}@github.com/tigerbeetle/devhubdb.git
+        \\  {credential_config}
+        \\  https://github.com/tigerbeetle/devhubdb.git
         \\  devhubdb
     , .{
-        .token = token orelse "",
+        .credential_config = credential_config,
     });
 
     try shell.pushd("./devhubdb");
```