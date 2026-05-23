# Archive Path Escapes Destination Tree

## Classification

Path traversal; high severity.

## Affected Locations

- `OpenBSD/Ustar.pm:176` — `next` (parses entry name)
- `OpenBSD/Ustar.pm:160` — `_parse_records` (XHDR path/linkpath overrides)
- `OpenBSD/Ustar.pm:619` — `OpenBSD::Ustar::HardLink::create` (uses
  `linkname` as a path inside `destdir`)

## Summary

`OpenBSD::Ustar::next` trusts the archive's `name`/`prefix` fields and the
optional XHDR `path` override during extraction. The resulting
`fullname()` is built by simple concatenation
(`$self->{destdir}.$self->{name}`), so an absolute path or `..` component
escapes the extraction tree. Hardlink entries additionally treat their
`linkname` field as a path under `destdir`, so a hardlink with
`linkname = ../../etc/shadow` resolves outside the tree even when the
entry name itself looks safe.

## Provenance

Verified from supplied source, reproducer evidence, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

Extended during review: the original report covered the entry `name`
only. Walking the extraction sinks confirmed that
`OpenBSD::Ustar::HardLink::create` builds
`link $self->{destdir}.$linkname, $self->fullname`, so an attacker-chosen
`linkname` with `..` or a leading `/` is just as effective at producing
out-of-tree filesystem operations as a malicious `name`. The XHDR
`linkpath` record overrides the linkname after the basic header is
parsed, so the validation has to run after both code paths.

Confidence: certain.

## Preconditions

Victim extracts an attacker-controlled ustar archive.

## Proof

The basic header in `next()` accepts any `name`/`prefix` combination and
stores `linkname` unchanged. Extraction sinks then use these values
without further checks:

- `OpenBSD::Ustar::File::create` calls `open(my $fh, '>', $self->fullname)`.
- `OpenBSD::Ustar::Dir::create` calls `_ensure_dir($self->fullname)`.
- `OpenBSD::Ustar::HardLink::create` calls
  `link $self->{destdir}.$linkname, $self->fullname`.
- Symlink, fifo, and device entries similarly use `$self->fullname`.

With `destdir = "/tmp/extract/"` and a name `../escaped`:

```text
fullname = "/tmp/extract/" . "../escaped"
         = "/tmp/extract/../escaped"
```

That resolves to `/tmp/escaped`. Absolute names skip the destdir prefix
when resolved by the kernel.

For the hardlink primitive, a benign-looking name combined with a
traversing linkname suffices:

```text
name      = harmless
linkname  = ../../etc/shadow
```

`link("/tmp/extract/../../etc/shadow", "/tmp/extract/harmless")` resolves
to `link("/etc/shadow", "/tmp/extract/harmless")`, creating a hardlink
that exposes the target.

## Why This Is A Real Bug

The archive entry name and link name are attacker-controlled input that
reach concrete filesystem operations (`open`, `mkdir`, `link`, `symlink`,
`mkfifo`, `mknod`) with no containment checks. A malicious package
repository or archive source can create or overwrite files outside the
extraction root, or hardlink sensitive files into it.

## Fix Requirement

Reject unsafe archive paths before object creation or extraction.
At minimum:

- reject absolute paths and `..` components in the entry name;
- apply the same validation after XHDR `path` overrides;
- apply the same validation to the `linkname` of hardlink entries
  (including after XHDR `linkpath` overrides).

Symlink targets are intentionally not validated by this finding: real
packages legitimately install symlinks pointing outside the package
tree. Symlink-redirection attacks are addressed separately in finding 004.

## Patch Rationale

The patch adds `_check_path($name)` for the absolute/`..` test and a
`_check_entry_paths($result)` helper that runs the test against
`$result->{name}` for every entry and against `$result->{linkname}`
when the entry is a hardlink. `_check_entry_paths` is invoked both
after the normal `_new_object` path and after `_parse_records` has
applied XHDR overrides, so neither the standard header nor an XHDR
record can sneak an unsafe path past the validator.

## Residual Risk

A symlink entry whose target traverses outside the extraction tree can
still be created (because symlink targets are intentionally
unvalidated). The risk that this enables redirection of a subsequent
file extraction is tracked by finding 004; the symlink target itself is
a path the kernel does not dereference until it is used.

## Patch

```diff
diff --git a/OpenBSD/Ustar.pm b/OpenBSD/Ustar.pm
index 0fce9df..e5cc626 100644
--- a/OpenBSD/Ustar.pm
+++ b/OpenBSD/Ustar.pm
@@ -173,6 +173,24 @@ sub _parse_records($self, $result, $h)
 	}
 }
 
+sub _check_path($self, $name)
+{
+	if ($name =~ m|^/|o || $name =~ m|(?:^|/)\.\.(?:/|$)|o) {
+		$self->_fatal("Unsafe archive path #1", $name);
+	}
+}
+
+sub _check_entry_paths($self, $result)
+{
+	$self->_check_path($result->{name});
+	# hardlink targets resolve under destdir; restrict them like names.
+	# symlink targets may legitimately point outside the archive, so they
+	# are intentionally not validated here (see O_NOFOLLOW protection).
+	if ($result->isHardLink) {
+		$self->_check_path($result->{linkname});
+	}
+}
+
 sub next($self)
 {
 	# get rid of the current object
@@ -244,6 +262,7 @@ sub next($self)
 		my $h = $self->_read_records($size);
 		$result = $self->next;
 		$self->_parse_records($result, $h);
+		$self->_check_entry_paths($result);
 		return $result;
 	}
 	if (defined $types->{$type}) {
@@ -252,6 +271,7 @@ sub next($self)
 		$self->_fatal("Unsupported type #1 (#2)", $type,
 		    $unsupported->{$type} // "unknown");
 	}
+	$self->_check_entry_paths($result);
 	if (!$result->isFile && $result->{size} != 0) {
 		$self->_fatal("Bad archive: non null size for #1 (#2)",
 		    $types->{$type}, $result->{name});
```
