// PoC for finding 011 — parseECHExt accepts trailing bytes on outer ECH.
//
// The outer ECH parser reads type, KDF, AEAD, configID, encap and payload but
// never checks that the cryptobyte input is empty afterwards. A malformed
// extension with two extra trailing bytes is accepted, exposing later HPKE
// handling to non-canonical input. The inner ECH path already checks Empty.

package tls

import (
	"bytes"
	"testing"
)

func TestPoC011OuterECHExtAcceptsTrailingBytes(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x00)           // outerECHExt
	buf.Write([]byte{0x00, 0x01}) // KDFID
	buf.Write([]byte{0x00, 0x01}) // AEADID
	buf.WriteByte(0x07)           // configID
	buf.Write([]byte{0x00, 0x03}) // encap length
	buf.Write([]byte{0x01, 0x02, 0x03})
	buf.Write([]byte{0x00, 0x03}) // payload length
	buf.Write([]byte{0x04, 0x05, 0x06})
	buf.Write([]byte{0xde, 0xad}) // trailing junk

	echType, _, configID, encap, payload, err := parseECHExt(buf.Bytes())
	if err != nil {
		t.Fatalf("expected nil error showing the bug, got %v", err)
	}
	if echType != outerECHExt {
		t.Fatalf("expected outer ECH ext, got %v", echType)
	}
	if configID != 7 {
		t.Fatalf("configID = %d, want 7", configID)
	}
	if !bytes.Equal(encap, []byte{1, 2, 3}) || !bytes.Equal(payload, []byte{4, 5, 6}) {
		t.Fatalf("decoded encap=%x payload=%x", encap, payload)
	}
	t.Logf("BUG REPRODUCED: parseECHExt accepted 2 trailing bytes (0xdead) without error")
}
