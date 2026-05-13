# Empty Yarn Spec Panics Name Extraction

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/install/yarn.rs:95`

`src/install/yarn.rs:376`

`src/install/yarn.rs:556`

## Summary

An attacker-controlled `yarn.lock` can contain an empty top-level spec such as `:` or `"":`. During Yarn v1 lockfile migration, the parser stores the empty spec, later passes it to name extraction, and triggers an out-of-bounds slice index panic. This aborts migration and causes an attacker-triggered denial of service.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim runs Yarn lockfile migration on an attacker-supplied repository.

## Proof

Minimal triggering lockfile:

```text
# yarn lockfile v1
:
  version "1.0.0"
```

Reachable flow:

- `migrate_yarn_lockfile` checks only for the Yarn v1 marker, then calls `YarnLock::parse(data)` before reading `package.json`.
- `YarnLock::parse` treats any top-level line ending in `:` as an entry.
- The key before `:` is split on commas, trimmed with `b" \""`, and stored in `current_specs` without rejecting empty slices.
- For `:` or `"":`, the resulting spec is empty.
- Entry finalization calls `consolidate_and_append_entry`.
- `consolidate_and_append_entry` sees `specs.len() == 1` and calls `Entry::get_name_from_spec(new_entry.specs[0])`.
- `Entry::get_name_from_spec` immediately reads `spec[0]`, panicking on an empty slice.

## Why This Is A Real Bug

The panic is deterministic for a syntactically reachable lockfile shape accepted by the migration parser. The attacker only needs to supply a repository containing a Yarn v1 lockfile with an empty top-level key. The victim’s migration process aborts before graceful error handling, preventing lockfile migration.

## Fix Requirement

Reject empty specs before storing them, or make all name/version helper routines safe for empty input.

## Patch Rationale

The patch rejects empty specs at parse time:

```diff
 let spec_trimmed = strings::trim(spec, b" \"");
+if spec_trimmed.is_empty() {
+    continue;
+}
 current_specs.push(spec_trimmed);
```

This prevents empty slices from entering `Entry.specs`, preserving the existing consolidation logic while eliminating the out-of-bounds access path. If every comma-separated spec is empty, `consolidate_and_append_entry` already handles `new_entry.specs.is_empty()` by returning early.

## Residual Risk

None

## Patch

`065-empty-yarn-spec-panics-name-extraction.patch` applies to `src/install/yarn.rs` and skips empty parsed specs before pushing them into `current_specs`.