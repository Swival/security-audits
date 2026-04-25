# ECHConfigList Parser Can Loop Forever

## Classification

Medium vulnerability. Confidence: certain.

## Affected Locations

`src/crypto/tls/ech.go:144`

## Summary

`parseECHConfigList` can enter an infinite loop when parsing an attacker-controlled `ECHConfigList` whose config length is `0xfffc`. The loop attempts to advance by `configLen + 4`, but the addition is performed as `uint16`, so `0xfffc + 4` wraps to `0` and the input slice never advances.

## Provenance

Verified from the provided reproducer and patch context. Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Attacker controls the `ECHConfigList` bytes passed to `parseECHConfigList`, including via `tls.Config.EncryptedClientHelloConfigList`.

## Proof

A malicious `ECHConfigList` can be constructed with:

- Outer list length bytes set to `00 00`.
- Total body length equal to `65536`, so `uint16(len(data)-2)` truncates to `0` and passes the length check.
- First config header set to unknown version `00 00`.
- Config length set to `ff fc`.

During parsing:

- `ech.go:131` compares the declared length to `uint16(len(data)-2)`, allowing `65536` to truncate to `0`.
- `ech.go:139` reads `configLen == 0xfffc`.
- `parseECHConfig` accepts the unknown-version config because `len(raw) >= int(Length)+4`.
- `ech.go:144` evaluates `configLen + 4` as `uint16`, which wraps to `0`.
- `s = s[configLen+4:]` becomes `s = s[0:]`, so `for len(s) > 0` never progresses.

The standalone PoC using the committed parser logic and vendored `cryptobyte` remained running past the timeout window, confirming non-termination.

## Why This Is A Real Bug

The loop termination depends on consuming bytes from `s` on every iteration. For `configLen == 0xfffc`, the parser validates enough input exists but then computes the slice offset in `uint16`, causing wraparound to zero. This violates the loop progress invariant and produces an infinite CPU spin on attacker-controlled input.

## Fix Requirement

Convert `configLen` to `int` before adding `4` so the slice offset cannot wrap in `uint16` arithmetic:

```go
s = s[int(configLen)+4:]
```

## Patch Rationale

The parser already validates the config length using integer-sized arithmetic in `parseECHConfig`. The patch preserves existing behavior while ensuring the loop advances by the actual encoded config size plus header size. Converting before addition prevents `uint16` overflow and restores guaranteed progress.

## Residual Risk

None

## Patch

`010-echconfiglist-parser-can-loop-forever.patch`

```diff
diff --git a/src/crypto/tls/ech.go b/src/crypto/tls/ech.go
--- a/src/crypto/tls/ech.go
+++ b/src/crypto/tls/ech.go
@@ -141,7 +141,7 @@ func parseECHConfigList(data []byte) ([]echConfig, error) {
 		if err != nil {
 			return nil, err
 		}
-		s = s[configLen+4:]
+		s = s[int(configLen)+4:]
 		configs = append(configs, config)
 	}
 	return configs, nil
```