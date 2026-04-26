// PoC for finding 015: ML-DSA sigGen handler swaps mu and context.
// requiredArgs declares the order: secret key, message, randomizer, mu,
// context. The handler parses args[3] as context and args[4] as mu, the
// reverse of the documented contract.
//
// Evidence: a request with a 64-byte mu at args[3] and an empty context at
// args[4] gets rejected as "unsupported" (handler sees haveMu == false). A
// request with the SAME mu at args[4] and empty args[3] succeeds. Both
// requests describe the same ACVP-level test according to the declared
// requiredArgs order, so they should produce identical signatures, but the
// first one fails entirely.

//go:build !fips140v1.0

package fipstest

import (
	"crypto/internal/fips140/mldsa"
	"strings"
	"testing"
)

func TestPoCMlDsaSigGenMuContextSwapped(t *testing.T) {
	cmd, ok := commands["ML-DSA-44/sigGen"]
	if !ok {
		t.Skip("ML-DSA-44/sigGen not registered")
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	sk, err := mldsa.NewPrivateKey44(seed)
	if err != nil {
		t.Fatalf("NewPrivateKey44: %v", err)
	}
	skBytes := mldsa.TestingOnlyPrivateKeySemiExpandedBytes(sk)

	mu := make([]byte, 64)
	for i := range mu {
		mu[i] = byte(i + 1)
	}

	// Per the handler's documented requiredArgs: sk, message, randomizer, mu, context.
	argsDocOrder := [][]byte{skBytes, nil, nil, mu, nil}
	_, errDoc := cmd.handler(argsDocOrder)

	// What the handler actually accepts because of the swap: sk, message, randomizer, context, mu.
	argsHandlerOrder := [][]byte{skBytes, nil, nil, nil, mu}
	resp, errImpl := cmd.handler(argsHandlerOrder)

	t.Logf("documented order: err=%v", errDoc)
	t.Logf("handler-internal order: err=%v len(sig)=%d", errImpl, lenOf(resp))

	if errDoc == nil {
		t.Fatalf("EXPECTED documented order to be rejected by buggy handler; got success")
	}
	if !strings.Contains(errDoc.Error(), "unsupported ML-DSA sigGen args") {
		t.Fatalf("unexpected error for documented order: %v", errDoc)
	}
	if errImpl != nil {
		t.Fatalf("EXPECTED handler-internal order to succeed; got %v", errImpl)
	}
	t.Log("BUG REPRODUCED: requests built from the declared argument contract are")
	t.Log("rejected as unsupported, while the same bytes shifted to match the")
	t.Log("buggy handler order succeed -- the handler reads context and mu")
	t.Log("from the wrong slots.")
}

func lenOf(resp [][]byte) int {
	if len(resp) == 0 {
		return 0
	}
	return len(resp[0])
}
