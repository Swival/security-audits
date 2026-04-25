# Oversized CMAC Panics

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140test/acvp_test.go:1545`

## Summary

`CMAC-AES/verify` accepts a claimed MAC from ACVP input and compares it against a computed CMAC tag by slicing the computed tag to `len(claimedMAC)`. If the claimed MAC is longer than the fixed CMAC tag length, Go panics with a slice bounds error and terminates the wrapper.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The ACVP wrapper receives a `CMAC-AES/verify` request.
- The request contains the expected 3 arguments.
- The claimed MAC argument is longer than the computed CMAC tag length.

## Proof

The finding was reproduced.

A request using:

- 16-byte zero AES key
- empty message
- 17-byte claimed MAC

reaches `cmdCmacAesVerifyAft` through `processingLoop`, which checks only the argument count before dispatch.

`cmdCmacAesVerifyAft` computes a 16-byte CMAC tag, then evaluates:

```go
tag[:len(claimedMAC)]
```

With a 17-byte claimed MAC, this causes:

```text
panic: runtime error: slice bounds out of range [:17] with length 16
```

The wrapper process terminates instead of returning verification failure or a normal processing error.

## Why This Is A Real Bug

The claimed MAC is attacker/tool-supplied input parsed by `readRequest`. The command handler accepts the request shape and reaches the vulnerable comparison without validating that the claimed MAC length is bounded by the computed tag length.

For oversized input, this is not a normal verification failure; it is a runtime panic that aborts the ACVP wrapper.

## Fix Requirement

Reject claimed MAC values whose length exceeds the computed CMAC tag length before slicing the computed tag.

## Patch Rationale

The patch adds an explicit length check before the slice operation. Oversized claimed MACs are handled as verification failures or normal errors rather than allowing an out-of-bounds slice.

This preserves valid behavior for claimed MACs whose length is less than or equal to the computed tag length while removing the panic condition.

## Residual Risk

None

## Patch

Patch file: `003-oversized-cmac-panics.patch`