// PoC for finding 002: cmdAesGcmOpen randNonce path slices ciphertext[-12:]
// without checking len(ciphertext) >= 12. A short ciphertext panics.
//
// Evidence: invoking the registered "AES-GCM-randnonce/open" command handler
// with a 5-byte ciphertext panics with "slice bounds out of range".

package fipstest

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestPoCAesGcmOpenShortRandNonce(t *testing.T) {
	cmd, ok := commands["AES-GCM-randnonce/open"]
	if !ok {
		t.Skip("AES-GCM-randnonce/open command not registered")
	}

	tagLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(tagLen, 16) // 16-byte tag
	key := make([]byte, 16)
	short := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	args := [][]byte{tagLen, key, short, nil, nil}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("EXPECTED a runtime panic from short ciphertext slicing; GOT no panic")
		}
		msg := ""
		switch v := r.(type) {
		case error:
			msg = v.Error()
		case string:
			msg = v
		default:
			msg = "<unknown>"
		}
		if !strings.Contains(msg, "out of range") {
			t.Logf("recovered non-bounds panic: %v", r)
		}
		t.Logf("BUG REPRODUCED: short ciphertext (%d bytes) panicked with: %v", len(short), r)
	}()

	_, err := cmd.handler(args)
	t.Fatalf("EXPECTED a panic; GOT err=%v (no panic)", err)
}
