// PoC for finding 069 — NewPrivateKeyECDH calls curveSize(curve) before
// curveNID(curve), so any unsupported curve string panics in curveSize
// instead of returning the existing unknown-curve error. The same problem
// affects names like "P-224" that curveNID may accept but curveSize does
// not, so this test exercises both paths.

//go:build boringcrypto && linux && (amd64 || arm64) && !android && !msan && cgo

package boring

import (
	"strings"
	"testing"
)

func TestPoC069UnknownPrivateCurvePanicsBogus(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from NewPrivateKeyECDH(\"bogus\", ...)")
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

	_, _ = NewPrivateKeyECDH("bogus", make([]byte, 32))
}

func TestPoC069UnknownPrivateCurvePanicsP224(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from NewPrivateKeyECDH(\"P-224\", ...) — curveSize does not support P-224")
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

	_, _ = NewPrivateKeyECDH("P-224", make([]byte, 28))
}
