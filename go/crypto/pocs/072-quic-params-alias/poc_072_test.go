// PoC for finding 072 — QUICConn.SetTransportParameters stores the caller's
// slice directly. Mutating the slice afterwards changes the bytes the
// handshake later sends to the peer. The fix is a defensive copy at the
// API boundary.

package tls

import (
	"bytes"
	"testing"
)

func TestPoC072TransportParametersAliasCaller(t *testing.T) {
	cfg := &QUICConfig{TLSConfig: &Config{MinVersion: VersionTLS13, InsecureSkipVerify: true}}
	q := QUICClient(cfg)

	params := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	original := append([]byte(nil), params...)
	q.SetTransportParameters(params)

	for i := range params {
		params[i] = 0xff
	}

	stored := q.conn.quic.transportParams
	t.Logf("caller passed:    %x", original)
	t.Logf("caller mutated:   %x", params)
	t.Logf("stored on QUICConn: %x", stored)

	if bytes.Equal(stored, original) {
		t.Fatal("stored slice differs from mutated caller slice — defensive copy already in place")
	}
	if !bytes.Equal(stored, params) {
		t.Fatalf("stored slice diverges from caller slice in an unexpected way; got %x", stored)
	}
	t.Log("BUG REPRODUCED: caller-side mutation of the params slice changed the bytes the handshake will marshal as transport parameters")
}
