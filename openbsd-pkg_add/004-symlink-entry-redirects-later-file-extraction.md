# Symlink Entry Redirects Later File Extraction

## Classification

Path traversal / arbitrary file overwrite via symlink-following extraction.

Severity: high.

Confidence: certain.

## Affected Locations

- `OpenBSD/Ustar.pm:650`
- `OpenBSD/Ustar.pm:777`

## Summary

`OpenBSD::Ustar` extracts archive entries sequentially. A crafted archive can first create a symlink at an archive path and then include a regular file entry with the same path. The regular file extraction opens that path with Perl `open '>'`, which follows the existing symlink and writes attacker-controlled file contents to the symlink target outside the extraction destination.

## Provenance

Reported and reproduced from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Victim extracts an attacker-controlled archive.
- Extraction destination is writable by the victim process.
- The symlink target is writable by the victim process.

## Proof

The documented extraction pattern processes each returned archive object in order with `$o->create`.

Relevant behavior:

- `OpenBSD::Ustar::SoftLink::create` creates archive-controlled symlinks with:
  - `symlink $self->{linkname}, $self->fullname`
- `OpenBSD::Ustar::File::create` later computes the same `fullname` for a regular file entry and opens it with:
  - `open(my $fh, '>', $self->fullname)`
- Perl `open '>'` follows an existing symlink.

Trigger archive layout:

```text
1. symlink entry:
   name = victim
   linkname = ../outside

2. regular file entry:
   name = victim
   contents = attacker-controlled bytes
```

When extracted, the first entry creates `dest/victim -> ../outside`. The second entry opens `dest/victim` for writing, follows the symlink, and truncates/overwrites `../outside`.

## Why This Is A Real Bug

The archive reader exposes entries sequentially, and extraction code is expected to call `create` for each entry. No check prevents a later regular file from reusing a path that was previously created as a symlink. Because the file open operation follows symlinks, archive contents can redirect writes outside the intended destination.

This is not limited to creating files inside the extraction tree; it can overwrite any symlink target reachable and writable by the victim process.

## Fix Requirement

Regular file extraction must not follow symlinks when opening the destination path. Existing symlink paths must be rejected rather than truncated or overwritten through the symlink target.

## Patch Rationale

The patch replaces Perl `open '>'` with `sysopen` using `O_NOFOLLOW`:

```perl
sysopen(my $fh, $self->fullname,
    O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW)
```

This preserves the intended behavior for normal file extraction while
causing extraction to fail if the destination path is an existing
symlink. `O_CREAT|O_TRUNC|O_WRONLY` maintains create/truncate/write
semantics for regular files, and `O_NOFOLLOW` blocks the
final-component redirection primitive used by the original exploit.

## Residual Risk

`O_NOFOLLOW` only protects the *last* component of the path. An
archive can still publish an intermediate symlink and then write
through it:

```text
1. symlink entry  name = subdir       linkname = ../../etc
2. file entry     name = subdir/foo
```

Combined with finding 003 (which rejects `..` and absolute paths in
the entry `name` but, by design, does not constrain symlink targets),
the file extraction would resolve `destdir/subdir/foo` through the
`subdir` symlink because `OpenBSD::Ustar::_ensure_dir` uses `-d $dir`,
which follows symlinks. The final `open` then opens
`/etc/foo` with `O_NOFOLLOW` — which only refuses to follow `foo`
itself, not the symlink in the parent component — and creates or
truncates the target.

Fully closing this gap requires either:

- validating symlink targets so they cannot point outside the
  destination tree (this would break legitimate packages that install
  symlinks to other parts of the filesystem); or
- resolving each component with `openat(.., O_NOFOLLOW)` while
  extracting, which is a larger restructuring of
  `OpenBSD::Ustar` than this finding attempts.

The `O_NOFOLLOW` change is still worth applying as defense in depth:
it eliminates the simplest and most direct variant of the attack and
documented exploit, and the more elaborate variant still requires a
signed package on the `pkg_add` path or a non-`pkg_add` consumer of
`OpenBSD::Ustar`.

## Patch

```diff
diff --git a/OpenBSD/Ustar.pm b/OpenBSD/Ustar.pm
index 0fce9df..b24b566 100644
--- a/OpenBSD/Ustar.pm
+++ b/OpenBSD/Ustar.pm
@@ -772,12 +772,14 @@ sub close($self)
 }
 
 package OpenBSD::Ustar::File;
+use Fcntl qw(O_CREAT O_NOFOLLOW O_TRUNC O_WRONLY);
 our @ISA=qw(OpenBSD::Ustar::Object);
 
 sub create($self)
 {
 	$self->_make_basedir;
-	open(my $fh, '>', $self->fullname) or
+	sysopen(my $fh, $self->fullname,
+	    O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW) or
 	    $self->_fatal("Can't write to #1: #2", $self->fullname, $!);
 	$self->extract_to_fh($fh);
 }
```