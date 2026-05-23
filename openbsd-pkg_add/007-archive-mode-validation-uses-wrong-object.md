# Archive Mode Validation Uses Wrong Object

## Classification

security_control_failure, high severity, confidence: certain

## Affected Locations

OpenBSD/ArcCheck.pm:159

## Summary

`verify_modes` intended to validate an archive entry’s mode against the corresponding packing-list item, including stricter defaults when the packing-list item omits `@mode`. Instead, it called `_strip_modes($o)` with the archive object as the policy item.

Because parsed archive objects always have `{mode}`, `_strip_modes` skipped the `!defined $item->{mode}` restrictions and returned the unsafe archive mode unchanged. As a result, archive entries with modes that should be rejected, such as writable-by-group/world modes, were accepted.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

A victim validates package archive metadata against a packing-list item without an explicit `@mode` annotation.

## Proof

The issue was reproduced with a crafted tar entry whose metadata matched the packing-list item except for an unsafe mode:

- Archive entry mode: `0666`
- Archive owner: `root`
- Archive group: `bin`
- Size: matches packing-list metadata
- Packing-list item: file entry with no `@mode`

`validate_meta` calls `verify_modes` to enforce archive mode validation. In the vulnerable code, `verify_modes` compared:

```perl
$o->{mode} != $o->_strip_modes($o)
```

Passing `$o` as the second argument caused `_strip_modes` to see a defined `{mode}` and skip the branch that strips unsafe writable bits for unannotated packing-list entries.

With the vulnerable code:

- `_strip_modes($o)` returned `0666`
- `verify_modes` accepted `0666`

With the intended packing-list item:

- `_strip_modes($item)` would normalize the allowed mode to `0644`
- `verify_modes` would reject `0666`

The accepted archive mode is then practically relevant during extraction: `OpenBSD/Ustar.pm:816` calls `_set_modes_on_object`, `OpenBSD/Ustar.pm:514` chmods to the archive mode, and `OpenBSD/Add.pm:315` only overrides the mode when the packing-list item has `@mode`. Therefore, omitted `@mode` leaves the unsafe archive mode installed.

## Why This Is A Real Bug

The validator’s security decision depends on packing-list policy metadata, but the implementation passed the archive object instead. This makes the default hardening path for entries without `@mode` unreachable during validation.

The result is a fail-open control failure: package metadata validation accepts file modes it was designed to reject. The bug is source-grounded and reproduced through `validate_meta`; external package repository trust and signature policy are separate controls and do not change this broken validation behavior.

## Fix Requirement

`verify_modes` must call `_strip_modes` with the packing-list item, not the archive object. Validation must also avoid mutating the archive object’s stored mode while comparing normalized mode values.

## Patch Rationale

The patch changes mode validation to compute a local normalized archive mode:

```perl
my $mode = $o->{mode} & ~(S_ISUID|S_ISGID);
```

It then compares that value against the packing-list-derived normalized policy mode:

```perl
$o->_strip_modes($item) & ~(S_ISUID|S_ISGID)
```

This restores the intended behavior for unannotated entries, including stripping unsafe writable bits, while preserving the existing special handling for `S_ISUID` and `S_ISGID`.

Avoiding direct mutation of `$o->{mode}` also prevents validation from changing archive metadata as a side effect.

## Residual Risk

None

## Patch

```diff
diff --git a/OpenBSD/ArcCheck.pm b/OpenBSD/ArcCheck.pm
index ce5dd35..14f4e62 100644
--- a/OpenBSD/ArcCheck.pm
+++ b/OpenBSD/ArcCheck.pm
@@ -167,8 +167,8 @@ sub verify_modes($o, $item)
 		}
 	}
 	# XXX /1
-	$o->{mode} &= ~(S_ISUID|S_ISGID);
-	if ($o->{mode} != $o->_strip_modes($o)) {
+	my $mode = $o->{mode} & ~(S_ISUID|S_ISGID);
+	if ($mode != ($o->_strip_modes($item) & ~(S_ISUID|S_ISGID))) {
 		$o->_errsay("Error: weird mode for #1: #2", $item->fullname,
 		    $o->_printable_mode);
 		    $result = 0;
```