# custom template auto-installs dependencies

## Classification

Trust-boundary violation. Severity: medium. Confidence: certain.

## Affected Locations

`packages/cli/src/commands/scripts/init.ts:300`

## Summary

Noninteractive `scripts init` automatically runs `bun install` inside a cloned custom template repository when `--template-repo` is supplied and `--skip-install` is not supplied. Because package manager lifecycle scripts are controlled by the cloned template, this crosses from an untrusted repository boundary into code execution with the user's privileges.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- User runs `scripts init` noninteractively by supplying `--name`.
- User supplies a custom template with `--template-repo` or `--repo`.
- User does not supply `--skip-install`.
- The cloned template contains a `package.json` with install lifecycle scripts or dependencies that run lifecycle scripts.

## Proof

Untrusted input enters through `args[ARG_TEMPLATE_REPO]` and is assigned to `selected.repo`. The command then clones `selected.repo` into `dirPath`.

After cloning, the install block checks only that `package.json` exists and that `--skip-install` is not explicitly true:

```ts
if (
  existsSync(`${dirPath}/package.json`) &&
  args[ARG_SKIP_INSTALL] !== true
) {
```

In noninteractive mode, `interactive` is false because `--name` was supplied. The original code therefore set `shouldInstall` to `true` without confirmation:

```ts
const shouldInstall = interactive
  ? await confirm("Install dependencies?")
  : true;
```

It then ran:

```ts
Bun.spawn(["bun", "install"], {
  cwd: dirPath,
  stdout: "ignore",
  stderr: "pipe",
});
```

Runtime reproduction used a local git template with this `package.json`:

```json
{
  "scripts": {
    "preinstall": "printf executed > /tmp/.../lifecycle-ran"
  }
}
```

Running:

```bash
bun packages/cli/src/index.ts scripts init --name victim --type standalone --template-repo /tmp/.../template --skip-git
```

completed successfully, printed `Dependencies installed.`, and created the lifecycle marker file containing `executed`.

## Why This Is A Real Bug

`--template-repo` accepts a user-provided repository URL or shorthand, not a trusted built-in template. Running `bun install` in that cloned directory executes template-controlled package lifecycle scripts. In noninteractive mode the user receives no confirmation prompt, so merely choosing a custom template repository implicitly grants that repository code execution during initialization.

This is a real trust-boundary violation because cloning template content is expected data ingestion, while dependency installation with lifecycle scripts is active execution.

## Fix Requirement

Custom template repositories must not auto-install dependencies in noninteractive mode without explicit user consent. The command must either require confirmation for custom repositories or default to skipping install unless installation is explicitly enabled.

## Patch Rationale

The patch changes the install decision so custom template repositories always require confirmation before dependency installation:

```diff
-      const shouldInstall = interactive
+      const shouldInstall = interactive || args[ARG_TEMPLATE_REPO]
         ? await confirm("Install dependencies?")
         : true;
```

This preserves existing behavior for trusted built-in templates in noninteractive mode while preventing silent lifecycle script execution for custom repositories. Interactive sessions continue to ask as before.

## Residual Risk

None

## Patch

`001-custom-template-auto-installs-dependencies.patch`

```diff
diff --git a/packages/cli/src/commands/scripts/init.ts b/packages/cli/src/commands/scripts/init.ts
index cba3449..4e4f595 100644
--- a/packages/cli/src/commands/scripts/init.ts
+++ b/packages/cli/src/commands/scripts/init.ts
@@ -298,7 +298,7 @@ export const scriptsInitCommand = defineCommand<InitArgs>({
       existsSync(`${dirPath}/package.json`) &&
       args[ARG_SKIP_INSTALL] !== true
     ) {
-      const shouldInstall = interactive
+      const shouldInstall = interactive || args[ARG_TEMPLATE_REPO]
         ? await confirm("Install dependencies?")
         : true;
       if (shouldInstall) {
```