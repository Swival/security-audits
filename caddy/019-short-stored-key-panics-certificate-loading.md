# Short Stored Key Panics Certificate Loading

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`modules/caddytls/storageloader.go:96`

## Summary

`StorageLoader.LoadCertificates()` loads certificate and key bytes from configured storage. In the PEM path, it slices `keyData[:40]` before checking that `keyData` is at least 40 bytes long. If storage returns a key object shorter than 40 bytes, Go panics with a slice bounds error, aborting TLS certificate loading and preventing service startup.

## Provenance

Verified from supplied source, reproducer evidence, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caddy is configured to use `tls.certificates.load_storage`.
- The configured `certmagic.Storage` backend returns attacker-controlled contents for the configured key object.
- The configured key object is shorter than 40 bytes.
- The certificate/key pair uses the default empty format or `pem`.

## Proof

`LoadCertificates()` reads the key object from storage:

```go
keyData, err := sl.storage.Load(sl.ctx, pair.Key)
```

For default or PEM format, execution reaches:

```go
if strings.Contains(string(keyData[:40]), "ENCRYPTED") {
```

When `keyData` is shorter than 40 bytes, this slice operation panics before `tls.X509KeyPair` is called.

The reproduced case used a temporary `certmagic.Storage` test stub returning a one-byte key slice, such as:

```go
[]byte("x")
```

This triggered:

```text
panic: runtime error: slice bounds out of range
```

The panic occurs during `StorageLoader.LoadCertificates()`. `modules/caddytls/tls.go:263` calls `loader.LoadCertificates()` during TLS app provisioning and handles returned errors only; no local recovery handles this panic. As a result, startup/provisioning aborts.

## Why This Is A Real Bug

The key bytes come directly from the configured storage backend. With attacker-controlled storage contents, a malformed key object shorter than 40 bytes deterministically triggers a runtime panic. This is not merely an invalid certificate error path: the function does not return an error and instead aborts execution through an unrecovered panic, causing denial of service during TLS startup.

## Fix Requirement

Avoid fixed-length slicing before validating length. The encrypted-key detection must inspect key data safely for all possible storage-returned byte slice lengths.

## Patch Rationale

The patch replaces the unsafe prefix slice with a safe search over the complete key buffer:

```diff
-if strings.Contains(string(keyData[:40]), "ENCRYPTED") {
+if strings.Contains(string(keyData), "ENCRYPTED") {
```

This removes the slice bounds panic for short key objects while preserving the intended rejection of encrypted private keys. For malformed short keys, execution now proceeds to `tls.X509KeyPair`, which returns a normal parse error instead of panicking.

## Residual Risk

None

## Patch

`019-short-stored-key-panics-certificate-loading.patch`

```diff
diff --git a/modules/caddytls/storageloader.go b/modules/caddytls/storageloader.go
index c9487e89..b41c8969 100644
--- a/modules/caddytls/storageloader.go
+++ b/modules/caddytls/storageloader.go
@@ -93,7 +93,7 @@ func (sl StorageLoader) LoadCertificates() ([]Certificate, error) {
 		case "pem":
 			// if the start of the key file looks like an encrypted private key,
 			// reject it with a helpful error message
-			if strings.Contains(string(keyData[:40]), "ENCRYPTED") {
+			if strings.Contains(string(keyData), "ENCRYPTED") {
 				return nil, fmt.Errorf("encrypted private keys are not supported; please decrypt the key first")
 			}
```