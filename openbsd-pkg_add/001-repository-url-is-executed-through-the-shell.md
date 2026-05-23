# Repository URL Is Executed Through The Shell

## Classification

Command execution; high severity; certain confidence.

## Affected Locations

`OpenBSD/PackageRepository.pm:825` — `exec($cmd)` sink.

Caller paths that feed the unsafe string into the sink:

- `OpenBSD/PackageRepository.pm:914` — HTTP/HTTPS listing
- `OpenBSD/PackageRepository.pm:1008` — FTP listing
- `OpenBSD/PackageRepository.pm:815` — `open_read_ftp` signature

## Summary

Repository listing for `http`, `https`, and `ftp` URLs builds a single shell command string containing the repository URL and executes it with Perl `exec($cmd)`. Because one-scalar `exec` invokes the shell when metacharacters are present, a caller-controlled repository URL can execute arbitrary shell commands during package listing.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- A caller can choose an `http`, `https`, or `ftp` repository URL.
- The chosen URL is used in a listing operation, such as package search or repository enumeration.
- The URL contains shell metacharacters.

## Proof

The HTTP listing path is:

```text
list()
obtain_list()
get_http_list()
open_read_ftp()
exec($cmd)
```

`get_http_list()` sets:

```perl
my $fullname = $self->url;
```

and then calls:

```perl
$self->open_read_ftp($self->ftp_cmd." -o - $fullname", $error)
```

`open_read_ftp()` drops privileges and then executes the single scalar command:

```perl
exec($cmd)
```

A concrete trigger is:

```sh
PKG_PATH='http://127.0.0.1:1/;id>/tmp/pkg-poc;#/' pkg_info -Q anything
```

That reaches a command equivalent to:

```sh
/usr/bin/ftp -o - http://127.0.0.1:1/;id>/tmp/pkg-poc;#/
```

The shell interprets `;id>/tmp/pkg-poc;#` before `ftp` receives the URL.

The FTP listing path is also vulnerable because it builds:

```perl
"echo 'nlist'| ".$self->ftp_cmd." $fullname"
```

and sends that string through the same `open_read_ftp()` scalar `exec` path.

## Why This Is A Real Bug

This is not only argument confusion or malformed URL handling. The URL is attacker-controlled input, concatenated into a command string, and passed to Perl `exec` in one-scalar form.

In Perl, `exec($cmd)` with a single scalar may invoke the shell when shell metacharacters are present. Therefore metacharacters embedded in the repository URL are interpreted as shell syntax.

Privilege dropping to `_pkgfetch` when invoked as root limits the execution identity, but it occurs before the shell execution and does not prevent command execution. If the caller is not root, the injected command runs as the invoking user.

## Fix Requirement

Repository URLs must never be interpolated into scalar shell command strings.

The fetch command must be invoked with argv-form `exec`, passing the URL as its own argument. FTP listing input such as `nlist` must be supplied through stdin without using a shell pipeline.

## Patch Rationale

The patch changes `open_read_ftp()` from accepting a shell command string to accepting structured process data:

```perl
sub open_read_ftp($self, $errors, $input, @args)
```

It now:

- Splits `ftp_cmd` into the executable and configured extra arguments.
- Builds `@cmd` as an argv array.
- Uses argv-form execution:

```perl
exec {$ftp} @cmd
```

- Passes HTTP/HTTPS URLs as separate arguments:

```perl
$self->open_read_ftp($error, undef, "-o", "-", $fullname)
```

- Replaces the FTP shell pipeline with stdin input:

```perl
$self->_list($error, "nlist\n", $fullname)
```

This removes both shell interpretation sites: the URL-bearing HTTP command string and the FTP `echo ... | ftp ...` command string.

## Residual Risk

None

## Patch

```diff
diff --git a/OpenBSD/PackageRepository.pm b/OpenBSD/PackageRepository.pm
index da59d8b..f653e19 100644
--- a/OpenBSD/PackageRepository.pm
+++ b/OpenBSD/PackageRepository.pm
@@ -812,18 +812,38 @@ sub grab_object($self, $object)
 	or $self->{state}->fatal("Can't run #1: #2", $self->ftp_cmd, $!);
 }
 
-sub open_read_ftp($self, $cmd, $errors = undef)
+sub open_read_ftp($self, $errors, $input, @args)
 {
+	my ($ftp, @extra) = split(/\s+/, $self->ftp_cmd);
+	my @cmd = ($ftp, @extra, @args);
+	my ($rdfh, $wrfh);
+	if (defined $input) {
+		pipe($rdfh, $wrfh);
+	}
 	my $child_pid = open(my $fh, '-|');
+	$self->did_it_fork($child_pid);
 	if ($child_pid) {
+		if (defined $input) {
+			close($rdfh);
+			local $SIG{'PIPE'} = 'IGNORE';
+			print $wrfh $input;
+			close($wrfh);
+		}
 		$self->{pipe_pid} = $child_pid;
 		return $fh;
 	} else {
 		open STDERR, '>>', $errors if defined $errors;
+		if (defined $input) {
+			close($wrfh);
+			open(STDIN, '<&', $rdfh) or
+			    $self->{state}->fatal("Bad dup: #1", $!);
+			close($rdfh);
+		}
 
 		$self->drop_privileges_and_setup_env;
-		exec($cmd) 
-		or $self->{state}->fatal("Can't run #1: #2", $cmd, $!);
+		exec {$ftp} @cmd
+		or $self->{state}->fatal("Can't run #1: #2",
+		    join(" ", @cmd), $!);
 	}
 }
 
@@ -911,8 +931,8 @@ sub get_http_list($self, $error)
 {
 	my $fullname = $self->url;
 	my $l = [];
-	my $fh = $self->open_read_ftp($self->ftp_cmd." -o - $fullname", 
-	    $error) or return;
+	my $fh = $self->open_read_ftp($error, undef, "-o", "-", $fullname)
+	    or return;
 	while(<$fh>) {
 		chomp;
 		for my $pkg (m/\<A[^>]*\s+HREF=\"(.*?\.tgz)\"/gio) {
@@ -985,10 +1005,10 @@ sub urlscheme($)
 	return 'ftp';
 }
 
-sub _list($self, $cmd, $error)
+sub _list($self, $error, $input, @args)
 {
 	my $l =[];
-	my $fh = $self->open_read_ftp($cmd, $error) or return;
+	my $fh = $self->open_read_ftp($error, $input, @args) or return;
 	while(<$fh>) {
 		chomp;
 		next if m/^\d\d\d\s+\S/;
@@ -1005,8 +1025,7 @@ sub _list($self, $cmd, $error)
 sub get_ftp_list($self, $error)
 {
 	my $fullname = $self->url;
-	return $self->_list("echo 'nlist'| ".$self->ftp_cmd." $fullname", 
-	    $error);
+	return $self->_list($error, "nlist\n", $fullname);
 }
 
 sub obtain_list($self, $error)
```