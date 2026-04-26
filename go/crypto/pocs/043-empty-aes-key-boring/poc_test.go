// PoC for finding 043 — empty AES key panics in BoringCrypto path.
//
// Place this file at /private/tmp/go/src/crypto/internal/boring/poc043_test.go
// and run on a host that actually links the BoringCrypto backend:
//
//   GOEXPERIMENT=boringcrypto go test -run TestPoC043 -v \
//       crypto/internal/boring
//
// On hosts where the boring stub is in effect (notboring.go), the test
// is skipped because Enabled is false. Where the bug is present, the
// test catches a runtime panic from indexing &c.key[0] on a zero-length
// slice, before the BoringCrypto C key-setup code can return the
// expected aesKeySizeError.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan && cgo

package boring

import (
	"testing"
)

func TestPoC043EmptyAESKey(t *testing.T) {
	if !Enabled {
		t.Skip("BoringCrypto not enabled in this build")
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic from empty key, got none")
		}
		t.Logf("PANIC: %v", r)
		t.Log("Empty key reaches &c.key[0] before BoringCrypto rejects the size,")
		t.Log("so the call panics instead of returning aesKeySizeError(0).")
	}()

	_, err := NewAESCipher([]byte{})
	t.Fatalf("expected panic, got err=%v", err)
}
