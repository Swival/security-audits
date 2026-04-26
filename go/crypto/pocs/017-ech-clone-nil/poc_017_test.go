// PoC for finding 017 — sendServerParameters does not check the return value
// of cloneHash before calling Write on it. cloneHash can return nil (hash
// without Clone or MarshalBinary support, or a marshal/unmarshal failure).
// At handshake_server_tls13.go:719 the code is:
//
//     echTranscript := cloneHash(hs.transcript, hs.suite.hash)
//     echTranscript.Write(hs.clientHello.original)
//
// A nil echTranscript leads to a nil-pointer panic in the handshake goroutine.
// This PoC mimics that exact sequence with a hash that does not implement
// Clone or BinaryMarshaler, demonstrating the panic.

package tls

import (
	"crypto"
	"hash"
	"testing"
)

type uncloneableHash struct{}

func (uncloneableHash) Write(p []byte) (int, error) { return len(p), nil }
func (uncloneableHash) Sum(b []byte) []byte         { return b }
func (uncloneableHash) Reset()                      {}
func (uncloneableHash) Size() int                   { return 32 }
func (uncloneableHash) BlockSize() int              { return 64 }

var _ hash.Hash = uncloneableHash{}

func TestPoC017UncheckedCloneHashPanics(t *testing.T) {
	echTranscript := cloneHash(uncloneableHash{}, crypto.SHA256)
	if echTranscript != nil {
		t.Fatal("expected cloneHash to return nil for a non-cloneable hash")
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected nil-pointer panic when calling Write on cloneHash result")
		}
		t.Logf("BUG REPRODUCED: cloneHash returned nil and a subsequent Write panicked: %v", r)
	}()

	echTranscript.Write([]byte("client hello"))
}
