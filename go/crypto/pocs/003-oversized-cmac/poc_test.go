// PoC for finding 003: cmdCmacAesVerifyAft slices the computed CMAC tag
// using len(claimedMAC) without bounding it. A 17-byte claimed MAC against
// a 16-byte AES CMAC tag triggers a slice-bounds panic.
//
// Evidence: handler call with claimedMAC of size 17 panics with
// "slice bounds out of range [:17] with length 16".

package fipstest

import (
	"strings"
	"testing"
)

func TestPoCCmacVerifyOversized(t *testing.T) {
	cmd, ok := commands["CMAC-AES/verify"]
	if !ok {
		t.Skip("CMAC-AES/verify command not registered")
	}

	key := make([]byte, 16)
	message := []byte{} // empty
	claimedMAC := make([]byte, 17)
	args := [][]byte{key, message, claimedMAC}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("EXPECTED a panic on oversized claimed MAC; GOT no panic")
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
		t.Logf("BUG REPRODUCED: 17-byte claimed MAC against 16-byte CMAC tag panicked: %v", r)
	}()

	_, err := cmd.handler(args)
	t.Fatalf("EXPECTED a panic; GOT err=%v (no panic)", err)
}
