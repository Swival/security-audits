// PoC for finding 016 — illegalClientHelloChange ignores PSK identity / binder
// changes between the original ClientHello and the second ClientHello after
// HelloRetryRequest. TLS 1.3 requires the second ClientHello to preserve the
// PSK extension, but illegalClientHelloChange does not compare pskIdentities or
// pskBinders. Two ClientHellos with different PSK identities are accepted as
// "not illegal", which is the bug.

package tls

import "testing"

func TestPoC016HRRAcceptsPSKIdentityChange(t *testing.T) {
	base := func() *clientHelloMsg {
		return &clientHelloMsg{
			vers:                         VersionTLS12,
			random:                       make([]byte, 32),
			sessionId:                    []byte{1, 2, 3},
			cipherSuites:                 []uint16{0x1301},
			compressionMethods:           []uint8{0},
			supportedVersions:            []uint16{VersionTLS13},
			supportedCurves:              []CurveID{X25519},
			supportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256},
			pskModes:                     []uint8{1},
			alpnProtocols:                []string{},
		}
	}

	ch1 := base()
	ch1.pskIdentities = []pskIdentity{{label: []byte("identity-A"), obfuscatedTicketAge: 1}}
	ch1.pskBinders = [][]byte{make([]byte, 32)}

	ch2 := base()
	ch2.pskIdentities = []pskIdentity{{label: []byte("identity-B"), obfuscatedTicketAge: 2}}
	ch2.pskBinders = [][]byte{make([]byte, 32)}

	if illegalClientHelloChange(ch2, ch1) {
		t.Fatal("unexpected: illegalClientHelloChange returned true (bug already fixed?)")
	}
	t.Logf("BUG REPRODUCED: PSK identity changed from %q to %q across HRR but illegalClientHelloChange returned false",
		ch1.pskIdentities[0].label, ch2.pskIdentities[0].label)
}
