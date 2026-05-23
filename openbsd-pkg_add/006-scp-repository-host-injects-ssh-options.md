# scp Repository Host Injects ssh Options

## Classification

Command execution; high severity.

## Affected Locations

OpenBSD/PackageRepository/SCP.pm:39

## Summary

An attacker-controlled `scp` repository URL can supply a host beginning with `-`. The SCP repository code passes that host directly to `ssh` without an option terminator, so `ssh` interprets it as a local option rather than a destination. Supplying an option such as `-oProxyCommand=...` causes local command execution as the package-manager process when the repository connection is initiated.

## Provenance

Verified and reproduced from scanner output provided by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The package manager is invoked with an attacker-controlled `scp` repository URL.

## Proof

`OpenBSD::PackageRepository::SCP::initiate()` starts SSH with:

```perl
open2($rdfh, $wrfh, OpenBSD::Paths->ssh,
    $self->{host}, 'perl', '-x');
```

The repository host is passed before any `--` option terminator and is not rejected when it begins with `-`.

A host such as:

```text
-oProxyCommand=sh -c 'id > pwned'
```

is therefore parsed by `ssh` as an SSH option. `ProxyCommand` is executed locally by `ssh` before the remote connection completes or fails.

The behavior was reproduced with an equivalent runtime command:

```sh
/usr/bin/ssh "-oProxyCommand=sh -c 'id > pwned'" perl -x
```

The SSH connection failed, but the local proxy command executed first.

## Why This Is A Real Bug

The vulnerable call uses an argv-style process invocation, which prevents shell metacharacter expansion but does not prevent option injection into the invoked program. Since `ssh` treats leading-dash operands as options until `--`, attacker-controlled repository hosts can change SSH behavior.

`ProxyCommand` is specifically security-relevant because it executes a local command. Reaching `initiate()` for an attacker-controlled SCP repository is sufficient to run attacker-chosen code under the package-manager process.

## Fix Requirement

The SSH invocation must not allow the repository host to be interpreted as an SSH option.

Required controls:

- Insert `--` before the host argument passed to `ssh`.
- Reject SCP host values beginning with `-`.

## Patch Rationale

The patch adds a defensive validation check before process creation:

```perl
if ($self->{host} =~ m/^-/o) {
    $self->{state}->fatal("Invalid scp host: #1", $self->{host});
}
```

This rejects option-shaped hostnames before they reach `ssh`.

The patch also changes the SSH argv to include an explicit option terminator:

```perl
open2($rdfh, $wrfh, OpenBSD::Paths->ssh,
    '--', $self->{host}, 'perl', '-x');
```

This ensures subsequent arguments are treated as operands by `ssh`, not as options.

## Residual Risk

None

## Patch

```diff
diff --git a/OpenBSD/PackageRepository/SCP.pm b/OpenBSD/PackageRepository/SCP.pm
index c25065e..aef83d7 100644
--- a/OpenBSD/PackageRepository/SCP.pm
+++ b/OpenBSD/PackageRepository/SCP.pm
@@ -37,8 +37,11 @@ sub initiate($self)
 {
 	my ($rdfh, $wrfh);
 
+	if ($self->{host} =~ m/^-/o) {
+		$self->{state}->fatal("Invalid scp host: #1", $self->{host});
+	}
 	$self->{controller} = open2($rdfh, $wrfh, OpenBSD::Paths->ssh,
-	    $self->{host}, 'perl', '-x');
+	    '--', $self->{host}, 'perl', '-x');
 	$self->{cmdfh} = $wrfh;
 	$self->{getfh} = $rdfh;
 	$wrfh->autoflush(1);
```