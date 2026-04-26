// PoC for finding 027 — xorNonceAEAD.Seal/Open mutate shared nonceMask state
// while the underlying AEAD reads from it. Concurrent callers using the same
// xorNonceAEAD instance can observe a corrupted nonce: the AEAD sees
// mask^A^B instead of mask^A. The fix derives the masked nonce in a per-call
// local buffer.
//
// We replace the underlying AEAD with a fake that delays reading the nonce
// long enough for a second goroutine to XOR a different nonce into the same
// shared nonceMask. Running with `go test -race` also surfaces the data race
// on f.nonceMask itself.

package tls

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type captureAEAD struct {
	mu       sync.Mutex
	captures [][]byte
	gate     *atomic.Int32
}

func (c *captureAEAD) NonceSize() int { return 12 }
func (c *captureAEAD) Overhead() int  { return 0 }

func (c *captureAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	c.gate.Add(1)
	for c.gate.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.captures = append(c.captures, append([]byte(nil), nonce...))
	c.mu.Unlock()
	return append(out, plaintext...)
}

func (c *captureAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return ciphertext, nil
}

func TestPoC027XORNonceRace(t *testing.T) {
	mask := [aeadNonceLength]byte{0, 1, 2, 3, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}

	var gate atomic.Int32
	sink := &captureAEAD{gate: &gate}
	shared := &xorNonceAEAD{nonceMask: mask, aead: sink}

	nonceA := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	nonceB := []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

	expected := func(n []byte) []byte {
		out := make([]byte, aeadNonceLength)
		copy(out, mask[:])
		for i, x := range n {
			out[4+i] ^= x
		}
		return out
	}
	corrupted := func() []byte {
		out := make([]byte, aeadNonceLength)
		copy(out, mask[:])
		for i, x := range nonceA {
			out[4+i] ^= x
		}
		for i, x := range nonceB {
			out[4+i] ^= x
		}
		return out
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		shared.Seal(nil, nonceA, []byte("msg-a"), nil)
	}()
	go func() {
		defer wg.Done()
		shared.Seal(nil, nonceB, []byte("msg-b"), nil)
	}()
	wg.Wait()

	expectedA := expected(nonceA)
	expectedB := expected(nonceB)

	t.Logf("expected nonces (one of):  %x  or  %x", expectedA, expectedB)
	t.Logf("corrupted (mask^A^B):      %x", corrupted)
	for i, c := range sink.captures {
		t.Logf("captured[%d]:              %x", i, c)
	}

	saw := false
	for _, c := range sink.captures {
		if !bytes.Equal(c, expectedA) && !bytes.Equal(c, expectedB) {
			saw = true
			t.Logf("BUG REPRODUCED: underlying AEAD saw nonce %x — neither expectedA nor expectedB", c)
		}
	}
	if !saw {
		t.Skipf("race did not interleave; rerun. Run with -race to see the data race on f.nonceMask regardless.")
	}
}
