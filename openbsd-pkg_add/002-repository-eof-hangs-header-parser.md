# Repository EOF Hangs HTTP Reader

## Classification

Denial of service, low severity. Confidence: certain.

## Affected Locations

- `OpenBSD/PackageRepository/HTTP.pm:128` — `getline`
- `OpenBSD/PackageRepository/HTTP.pm:98` — `get_header`
- `OpenBSD/PackageRepository/HTTP.pm:140` — `retrieve`
- `OpenBSD/PackageRepository/HTTP.pm:152` — `retrieve_and_print`
- `OpenBSD/PackageRepository/HTTP.pm:170` — `retrieve_chunked`

## Summary

An attacker-controlled (or merely broken) HTTP repository can close, stall,
or truncate the connection at any point during header or body delivery.
Every byte-level read loop in the HTTP proxy module reads with
`$self->{fh}->recv(…)` and ignores the result, so an EOF leaves the loop
condition unchanged forever and the proxy batch child hangs instead of
producing `SUCCESS`, `TRANSFER`, or `ERROR`. The result is a silent
denial of service of any package listing or fetch operation.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Reproduced and extended during review: the original report focused on the
header path, but the same `recv`-without-error-checking pattern is present
in all three body-reading loops, so a server can also hang the client
mid-body after returning a perfectly valid `Content-Length` or chunked
header.

## Preconditions

The client fetches package data from an HTTP repository that closes the
connection, withholds bytes, or sends a truncated response. With proxies
or unauthenticated HTTP this can also be a network attacker.

## Proof

`get_directory` and `get_file` both call `_Proxy::Connection->get_header`
and then `retrieve_response*` to fetch the body.

In the unpatched code:

- `getline` loops `while (1)` and only breaks when `$self->{buffer}`
  contains `\015\012`. EOF from `recv` returns `undef`/empty without
  mutating the buffer, so the loop spins.
- `retrieve` loops `while (length($self->{buffer}) < $sz)`. Reading fewer
  bytes than promised never advances the buffer length on EOF, so the
  loop spins.
- `retrieve_and_print` loops `while ($retrieved < $sz)` and increments
  `$retrieved` by `length($result)`. An EOF leaves `$result` empty, so
  the counter never advances.
- `retrieve_chunked` repeatedly calls `getline` to read the chunk-size
  line. If `getline` hangs, this hangs too; if `getline` is fixed but
  returns `undef`, the existing `if ($sz =~ m/^([0-9a-fA-F]+)/)` test
  fails silently and the `while (1)` loop never terminates.

A local server that sends `HTTP/1.1 200` without CRLF and closes
the connection drives the unpatched `getline` into a busy loop (>2.5M
`recv` calls per second observed before an alarm fired).

## Fix Requirement

Every `recv`-driven loop in `_Proxy::Connection` must detect EOF or
socket error and propagate failure so that callers can exit through their
existing error paths.

## Patch Rationale

`getline` returns `undef` when `recv` reports an error or empty buffer.
`get_header` handles `undef` for both the status line and subsequent
header lines.

`retrieve` mirrors the same EOF detection and returns whatever bytes it
did receive (possibly an empty string) plus a `defined`-able signal: on
EOF it returns `undef`, on success it returns the requested chunk.

`retrieve_and_print` bails out of its loop on EOF after flushing any
already-received bytes, so the caller stops looping.

`retrieve_chunked` propagates an `undef` from `getline` by returning
`undef` itself, breaking what would otherwise be an infinite outer loop.

`retrieve_response` and `retrieve_response_and_print` propagate the new
return values, and the existing `if (!defined $r) … exit 1;` branch in
`get_directory` (HTTP.pm) now also catches body-read failures.

## Residual Risk

A pathologically slow server can still keep the proxy child alive
indefinitely if it dribbles one byte every read; this finding only
addresses outright EOF and error. A separate idle/total timeout would be
required to bound runtime under that scenario.

## Patch

```diff
diff --git a/OpenBSD/PackageRepository/HTTP.pm b/OpenBSD/PackageRepository/HTTP.pm
index b5a6712..2f0092b 100755
--- a/OpenBSD/PackageRepository/HTTP.pm
+++ b/OpenBSD/PackageRepository/HTTP.pm
@@ -98,12 +98,14 @@ sub send_header($o, $document, %extra)
 sub get_header($o)
 {
 	my $l = $o->getline;
-	if ($l !~ m,^HTTP/1\.1\s+(\d\d\d),) {
+	if (!defined $l || $l !~ m,^HTTP/1\.1\s+(\d\d\d),) {
 		return undef;
 	}
 	my $h = _Proxy::Header->new;
 	$h->{code} = $1;
-	while ($l = $o->getline) {
+	while (1) {
+		$l = $o->getline;
+		return undef if !defined $l;
 		last if $l =~ m/^$/;
 		if ($l =~ m/^([\w\-]+)\:\s*(.*)$/) {
 			$h->{$1} = $2;
@@ -132,17 +134,21 @@ sub getline($self)
 			return $1;
 		}
 		my $buffer;
-		$self->{fh}->recv($buffer, 1024);
+		return undef
+		    if !defined $self->{fh}->recv($buffer, 1024)
+		    || $buffer eq '';
 		$self->{buffer}.=$buffer;
     	}
 }
 
 sub retrieve($self, $sz)
 {
 	while(length($self->{buffer}) < $sz) {
 		my $buffer;
-		$self->{fh}->recv($buffer, $sz - length($self->{buffer}));
+		return undef
+		    if !defined $self->{fh}->recv($buffer,
+			    $sz - length($self->{buffer}))
+		    || $buffer eq '';
 		$self->{buffer}.=$buffer;
 	}
 	my $result= substr($self->{buffer}, 0, $sz);
@@ -161,7 +167,9 @@ sub retrieve_and_print($self, $sz, $fh)
 		$self->{buffer} = '';
 	}
 	while ($retrieved < $sz) {
-		$self->{fh}->recv($result, $sz - $retrieved);
+		last
+		    if !defined $self->{fh}->recv($result, $sz - $retrieved)
+		    || $result eq '';
 		print $fh $result;
 		$retrieved += length($result);
 	}
@@ -172,6 +180,7 @@ sub retrieve_chunked($self)
 	my $result = '';
 	while (1) {
 		my $sz = $self->getline;
+		return undef if !defined $sz;
 		if ($sz =~ m/^([0-9a-fA-F]+)/) {
 			my $realsize = hex($1);
 			last if $realsize == 0;
```
