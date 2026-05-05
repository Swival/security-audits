# Hidden Precompressed Sidecar Can Be Served

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

`modules/caddyhttp/fileserver/staticfiles.go:425`

## Summary

Caddy's file server applies `hide` rules to the resolved requested file, but not to precompressed sidecar files selected via `Accept-Encoding`. If a visible file has a precompressed sidecar that matches the hide list, a remote HTTP client can request the visible file with a supported encoding and receive the hidden sidecar content.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Precompressed file serving is enabled.
- A visible base file exists, such as `public.txt`.
- A matching precompressed sidecar exists, such as `public.txt.gz`.
- The sidecar path matches the configured `hide` list, such as `*.gz`.
- The attacker can send an HTTP request with an `Accept-Encoding` value that selects the hidden sidecar.

## Proof

`ServeHTTP` checks hiding for the resolved requested file before precompressed handling:

- `fileHidden(filename, filesToHide)` is applied to the visible resolved file.
- The precompressed loop then constructs `compressedFilename := filename + precompress.Suffix()`.
- It calls `fs.Stat(fileSystem, compressedFilename)` and `openFile(fileSystem, compressedFilename, w)` without checking `fileHidden(compressedFilename, filesToHide)`.
- It sets `Content-Encoding` and serves the sidecar bytes.

Runtime proof of concept used a temporary root containing:

```text
public.txt = "VISIBLE"
public.txt.gz = "SECRET-SIDECAR"
Hide: []string{"*.gz"}
gzip precompressed enabled
```

Requesting the visible file with gzip accepted produced:

```text
status=200
content-encoding="gzip"
body="SECRET-SIDECAR"
```

This demonstrates that the hidden `public.txt.gz` sidecar is served even though direct access to `*.gz` is blocked by the hide list.

## Why This Is A Real Bug

The `hide` setting is intended to make matching files unavailable through the file server. The direct file path honors this policy, and index-file selection also skips hidden candidates. The precompressed sidecar path bypasses the same policy check, so attacker-controlled content negotiation changes the served filesystem path from a visible file to a hidden file.

The disclosed bytes come from a file that the configured hide list would otherwise block, making this an externally triggerable information disclosure.

## Fix Requirement

Before statting or opening any precompressed sidecar, call `fileHidden(compressedFilename, filesToHide)`. If the sidecar is hidden, skip it and continue evaluating other encodings or fall back to the original visible file.

## Patch Rationale

The patch inserts the missing hide-policy check immediately after constructing the precompressed sidecar path and before any filesystem access to that sidecar. This matches the existing behavior for requested files and index files: hidden candidates are treated as unavailable.

Skipping hidden sidecars preserves normal precompressed serving for allowed sidecars while preventing content negotiation from bypassing `hide`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/fileserver/staticfiles.go b/modules/caddyhttp/fileserver/staticfiles.go
index dce40302..8bbfa92a 100644
--- a/modules/caddyhttp/fileserver/staticfiles.go
+++ b/modules/caddyhttp/fileserver/staticfiles.go
@@ -439,6 +439,9 @@ func (fsrv *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request, next c
 			continue
 		}
 		compressedFilename := filename + precompress.Suffix()
+		if fileHidden(compressedFilename, filesToHide) {
+			continue
+		}
 		compressedInfo, err := fs.Stat(fileSystem, compressedFilename)
 		if err != nil || compressedInfo.IsDir() {
 			if c := fsrv.logger.Check(zapcore.DebugLevel, "precompressed file not accessible"); c != nil {
```