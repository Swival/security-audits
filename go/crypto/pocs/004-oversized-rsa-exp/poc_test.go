// PoC for finding 004: cmdRsaSigVerAft computes paddedE := make([]byte, 4)
// then copies eBytes into paddedE[4-len(eBytes):], without bounding
// len(eBytes) <= 4. A 5-byte exponent yields the slice expression
// paddedE[-1:] which panics.
//
// Evidence: invoking RSA/sigVer/SHA2-256/pkcs1v1.5 with a 5-byte exponent
// panics with "slice bounds out of range [-1:]".

package fipstest

import (
	"strings"
	"testing"
)

func TestPoCRsaSigVerOversizedExponent(t *testing.T) {
	cmd, ok := commands["RSA/sigVer/SHA2-256/pkcs1v1.5"]
	if !ok {
		t.Skip("RSA/sigVer/SHA2-256/pkcs1v1.5 command not registered")
	}

	n := make([]byte, 256)                         // dummy modulus content; never reached
	n[0] = 0xff                                    // arbitrary
	eBytes := []byte{0x01, 0x00, 0x01, 0x00, 0x00} // 5 bytes
	msg := []byte("hi")
	sig := make([]byte, 256)
	args := [][]byte{n, eBytes, msg, sig}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("EXPECTED a panic on 5-byte exponent slicing; GOT no panic")
		}
		msg := ""
		switch v := r.(type) {
		case error:
			msg = v.Error()
		case string:
			msg = v
		}
		if !strings.Contains(msg, "out of range") {
			t.Logf("recovered non-bounds panic: %v", r)
		}
		t.Logf("BUG REPRODUCED: 5-byte e (paddedE[4-5:] == paddedE[-1:]) panicked: %v", r)
	}()

	_, err := cmd.handler(args)
	t.Fatalf("EXPECTED a panic; GOT err=%v (no panic)", err)
}
