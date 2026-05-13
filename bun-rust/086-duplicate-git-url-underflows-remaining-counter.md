# Duplicate Git URL Underflows Remaining Counter

## Classification

Denial of service, medium severity.

## Affected Locations

`src/install/PackageManager/PackageJSONEditor.rs:748`

## Summary

A single Git/GitHub update request can match identical Git URL values across multiple dependency groups. Each match decrements `remaining`, but the original code only exits the current property loop, not the outer dependency-group scan. Duplicate Git URLs can therefore decrement `remaining` more than once for one update, causing unsigned underflow or an enormous allocation target later in `PackageJSONEditor::edit`.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs `bun add` or matching `bun update` in an attacker-controlled repository.
- The repository `package.json` contains the same Git/GitHub URL in more than one dependency group.
- The command targets that same Git/GitHub URL.

## Proof

Concrete malicious `package.json` trigger:

```json
{
  "devDependencies": {
    "a": "git+https://example.com/repo.git"
  },
  "optionalDependencies": {
    "b": "git+https://example.com/repo.git"
  }
}
```

Victim command:

```sh
bun add git+https://example.com/repo.git
```

Execution reaches `PackageJSONEditor::edit` before install via `src/install/PackageManager/updatePackageJSONAndInstall.rs:315`.

In the Git/GitHub URL fallback, a matching dependency value sets `request.e_string` and executes `remaining -= 1`. The original `break` exits only the inner property loop. Scanning then continues into later dependency groups, where the same URL can match again and decrement `remaining` again for the same request.

With one update request and two matching dependency groups, `remaining` is decremented from `1` to `0`, then again from `0`. This underflows with overflow checks or wraps. The wrapped value later feeds:

```rust
let target = dependencies.len() + remaining - replacing;
```

at `src/install/PackageManager/PackageJSONEditor.rs:773`, causing an enormous dependency vector growth loop at `src/install/PackageManager/PackageJSONEditor.rs:774` and resulting in panic or memory exhaustion.

## Why This Is A Real Bug

The edit logic tracks how many update requests still need new dependency entries. That counter must be decremented at most once per request. The Git/GitHub fallback violates this invariant because the same request can be matched repeatedly across dependency groups by value rather than by package name.

The reproducer uses only attacker-controlled `package.json` content and a normal `bun add` command. The impact is a local denial of service during dependency editing before installation completes.

## Fix Requirement

Stop dependency-group scanning after the first Git/GitHub URL match for a request, or otherwise ensure `remaining` is decremented only once per request.

## Patch Rationale

The patch labels the dependency-group loop and changes the Git/GitHub URL match from an unlabeled `break` to `break 'dependency_group`.

This preserves the intended behavior of reusing the first matching existing dependency string while preventing subsequent dependency groups from matching the same request and decrementing `remaining` again.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/PackageManager/PackageJSONEditor.rs b/src/install/PackageManager/PackageJSONEditor.rs
index 6a19c8560a..98d3561b8b 100644
--- a/src/install/PackageManager/PackageJSONEditor.rs
+++ b/src/install/PackageManager/PackageJSONEditor.rs
@@ -613,7 +613,7 @@ pub fn edit(
             'loop_: while i < updates.len() {
                 let request = &mut updates[i];
                 // order-insensitive scan: `FOUR` is fine here
-                for list in DependencyGroup::FOUR.map(|g| g.prop) {
+                'dependency_group: for list in DependencyGroup::FOUR.map(|g| g.prop) {
                     if let Some(query) = current_package_json.as_property(list) {
                         if matches!(query.expr.data, bun_ast::ExprData::EObject(_)) {
                             let name = request.get_name();
@@ -745,7 +745,7 @@ pub fn edit(
                                                             .as_ptr(),
                                                     );
                                                     remaining -= 1;
-                                                    break;
+                                                    break 'dependency_group;
                                                 }
                                             }
                                         }
```