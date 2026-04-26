// PoC for finding 051 — ExpandLabel truncates the encoded length when the
// caller asks for more than 65535 bytes. The HKDF label encodes length as
// uint16 but the original int length is passed to hkdf.Expand. For
// length == 65536 the encoded label says 0 while the underlying HKDF tries
// to produce 65536 bytes, leading to a counter-overflow panic in hkdf.Expand.

package tls13

import (
	"crypto/internal/fips140/sha256"
	"hash"
	"testing"
)

func TestPoC051HKDFLabelLengthTruncation(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from hkdf.Expand counter overflow")
		}
		t.Logf("BUG REPRODUCED: ExpandLabel(length=65536) panicked: %v", r)
	}()

	secret := make([]byte, 32)
	context := []byte("ctx")
	_ = ExpandLabel(func() hash.Hash { return sha256.New() }, secret, "test", context, 65536)
}
