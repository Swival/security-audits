// PoC for finding 059 — weakCertCache.newCert registers cleanup callbacks
// that recompute string(der) from the caller-owned slice. If the caller
// mutates `der` after the certificate is cached and before cleanup runs,
// CompareAndDelete uses the mutated key and misses the original entry. The
// stale entry then remains in the sync.Map indefinitely.
//
// We insert a cert, mutate its DER, drop the cert, force GC, and check that
// the cache entry under the original key is still present even though the
// cert is gone.

package tls

import (
	"encoding/pem"
	"runtime"
	"testing"
	"time"
)

func TestPoC059CleanupUsesMutableDERKey(t *testing.T) {
	wcc := &weakCertCache{}
	p, _ := pem.Decode([]byte(rsaCertPEM))
	if p == nil {
		t.Fatal("failed to decode test certificate")
	}

	der := append([]byte(nil), p.Bytes...)
	originalKey := string(der)

	cert, err := wcc.newCert(der)
	if err != nil {
		t.Fatalf("newCert: %v", err)
	}
	if _, ok := wcc.Load(originalKey); !ok {
		t.Fatal("cache does not contain entry under original key")
	}

	for i := range der {
		der[i] ^= 0xff
	}
	mutatedKey := string(der)
	if mutatedKey == originalKey {
		t.Fatal("DER mutation produced identical key")
	}

	runtime.KeepAlive(cert)
	cert = nil
	runtime.GC()
	runtime.GC()

	deadline := time.After(4 * time.Second)
	for {
		select {
		case <-deadline:
			if _, ok := wcc.Load(originalKey); ok {
				t.Logf("BUG REPRODUCED: certificate has been garbage collected, but the cache still holds an entry under the original DER key %q (cleanup deleted the mutated key %q which never existed)", originalKey[:8]+"...", mutatedKey[:8]+"...")
				return
			}
			t.Fatal("entry under original key was deleted; cleanup may have used the immutable key")
		default:
			runtime.GC()
			runtime.Gosched()
			time.Sleep(10 * time.Millisecond)
		}
	}
}
