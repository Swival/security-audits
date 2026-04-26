// PoC for finding 053 — TLS 1.0/1.1 EKM passes the caller-supplied negative
// length straight to prf10, which calls make([]byte, keyLen). Go's runtime
// panics with "len out of range" instead of returning a normal error.

package tls

import (
	"strings"
	"testing"
)

func TestPoC053NegativeEKMLengthPanics(t *testing.T) {
	suite := cipherSuiteByID(TLS_RSA_WITH_AES_128_CBC_SHA)
	if suite == nil {
		t.Fatal("could not find a TLS 1.0 cipher suite")
	}

	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	ekm := ekmFromMasterSecret(VersionTLS10, suite, masterSecret, clientRandom, serverRandom)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from negative EKM length")
		}
		msg, _ := r.(error)
		s := ""
		if msg != nil {
			s = msg.Error()
		} else if str, ok := r.(string); ok {
			s = str
		}
		if !strings.Contains(s, "len out of range") && !strings.Contains(s, "makeslice") {
			t.Logf("got unexpected panic value: %v (%T)", r, r)
		}
		t.Logf("BUG REPRODUCED: negative EKM length triggered runtime panic: %v", r)
	}()

	_, _ = ekm("EXPORTER-test", nil, -1)
}
