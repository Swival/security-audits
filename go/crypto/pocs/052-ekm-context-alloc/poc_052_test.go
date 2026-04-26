// PoC for finding 052 — TLS 1.0-1.2 EKM allocates the seed buffer using
// len(context) before checking that len(context) < 1<<16. An oversized
// context is rejected, but only after a backing array of roughly
// (clientRandom + serverRandom + 2 + len(context)) bytes is allocated.
//
// The test passes a 256 MiB context, captures the heap delta, and confirms
// the function returned the expected "context too long" error.

package tls

import (
	"runtime"
	"strings"
	"testing"
)

func TestPoC052OversizedEKMContextAllocates(t *testing.T) {
	suite := cipherSuiteByID(TLS_RSA_WITH_AES_128_GCM_SHA256)
	if suite == nil {
		t.Fatal("could not find a TLS 1.2 cipher suite")
	}

	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	ekm := ekmFromMasterSecret(VersionTLS12, suite, masterSecret, clientRandom, serverRandom)

	const ctxSize = 256 << 20 // 256 MiB
	context := make([]byte, ctxSize)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	out, err := ekm("EXPORTER-test", context, 32)

	runtime.ReadMemStats(&after)

	if out != nil {
		t.Fatal("expected nil output for oversized context")
	}
	if err == nil || !strings.Contains(err.Error(), "context too long") {
		t.Fatalf("expected context-too-long error, got %v", err)
	}

	deltaAlloc := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	t.Logf("error returned (correctly): %v", err)
	t.Logf("context size:               %d bytes", ctxSize)
	t.Logf("TotalAlloc delta around EKM call: %d bytes (~%d MiB)", deltaAlloc, deltaAlloc>>20)

	if deltaAlloc < ctxSize {
		t.Fatalf("expected at least %d bytes of additional allocation; got %d", ctxSize, deltaAlloc)
	}
	t.Logf("BUG REPRODUCED: oversized EKM context triggered ~%d MiB of allocation before the validation rejected it", deltaAlloc>>20)
}
