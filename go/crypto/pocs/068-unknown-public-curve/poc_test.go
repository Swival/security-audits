// PoC for finding 068 — NewPublicKeyECDH calls curveSize(curve) before
// curveNID(curve), so an unsupported curve string takes the panic path
// `panic("crypto/internal/boring: unknown curve " + curve)` instead of
// returning the existing unknown-curve error.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan && cgo

package boring

import (
	"strings"
	"testing"
)

func TestPoC068UnknownPublicCurvePanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from NewPublicKeyECDH(unknown curve)")
		}
		s := ""
		switch v := r.(type) {
		case string:
			s = v
		case error:
			s = v.Error()
		}
		if !strings.Contains(s, "unknown curve") {
			t.Logf("got panic value: %v", r)
		}
		t.Logf("PANIC AS EXPECTED: %v", r)
	}()

	_, _ = NewPublicKeyECDH("not-a-curve", make([]byte, 65))
}
