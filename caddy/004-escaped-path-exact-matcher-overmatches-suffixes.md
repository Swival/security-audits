# Escaped Path Exact Matcher Overmatches Suffixes

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`modules/caddyhttp/matchers.go:528`

## Summary

`MatchPath` exact patterns containing percent escapes are routed to `matchPatternWithEscapeSequence`. That helper can stop after consuming only the escaped matcher prefix and then run `path.Match` against the constructed prefix string. As a result, an exact escaped-path matcher such as `/foo%2fbar` also matches `/foo%2Fbar/baz`, allowing a remote client to select route policy intended only for the exact path.

## Provenance

Verified from supplied source, reproduced by runtime PoC, and patched according to the provided diff.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Server config uses an exact `MatchPath` pattern containing a percent escape.
- A route, policy, or handler decision depends on that path matcher.
- Attacker can send an HTTP request with an escaped path beginning with the exact matcher plus an added suffix.

## Proof

Relevant control flow:

- `modules/caddyhttp/matchers.go:480` sends any path matcher containing `%` to `matchPatternWithEscapeSequence`.
- `modules/caddyhttp/matchers.go:557` exits the helper loop when either the pattern or escaped request path reaches EOF.
- `modules/caddyhttp/matchers.go:642` then calls `path.Match` against the constructed string without requiring `iPath == len(escapedPath)`.
- Runtime PoC confirms `MatchPath{"/foo%2fbar"}` returns `true` for request URI `/foo%2Fbar/baz`.
- The non-escaped exact matcher control does not match `/foo/bar/baz`.
- `r.URL.EscapedPath()` preserves the attacker-supplied escaped request path, and `modules/caddyhttp/routes.go:271` uses the matcher result to decide route applicability.

Concrete impact:

```text
Configured exact escaped matcher: /foo%2fbar
Attacker request URI:          /foo%2Fbar/baz
Observed result:               matched
Expected result:               not matched
```

## Why This Is A Real Bug

The documented matcher behavior states that `/foo%2Fbar` should match precisely `/foo%2Fbar`, not `/foo/bar`. Exact path matching is also described as exact, not prefix-based.

The vulnerable helper violates that contract because it accepts after pattern exhaustion without verifying that the escaped request path was also exhausted. This turns exact escaped-path matchers into prefix matchers for suffixed attacker-controlled paths. Since matchers gate route, policy, and handler selection, the behavior can apply exact-only policy to paths outside the intended scope.

## Fix Requirement

For escaped-path exact matching, require both cursors to reach the end before accepting the constructed comparison:

- `iPattern == len(matchPath)`
- `iPath == len(escapedPath)`

If either side has unconsumed bytes, the match must fail.

## Patch Rationale

The patch adds an end-of-input invariant immediately after the lock-step scan:

```go
if iPattern != len(matchPath) || iPath != len(escapedPath) {
	return false
}
```

This prevents suffix overmatch by rejecting cases where the pattern was fully consumed but the escaped request path still contains extra bytes. It also rejects truncated request paths where the escaped path ends before the matcher pattern is fully consumed.

The check is placed before `%*` normalization and `path.Match`, so only fully consumed escaped-path candidates reach glob comparison.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/matchers.go b/modules/caddyhttp/matchers.go
index f179b9c1..79689e15 100644
--- a/modules/caddyhttp/matchers.go
+++ b/modules/caddyhttp/matchers.go
@@ -635,6 +635,10 @@ func (MatchPath) matchPatternWithEscapeSequence(escapedPath, matchPath string) b
 		iPattern++
 	}
 
+	if iPattern != len(matchPath) || iPath != len(escapedPath) {
+		return false
+	}
+
 	// we can now treat rawpath globs (%*) as regular globs (*)
 	matchPath = strings.ReplaceAll(matchPath, "%*", "*")
```