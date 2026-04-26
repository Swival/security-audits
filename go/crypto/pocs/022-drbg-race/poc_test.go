// PoC for finding 022: drbg.testingReader is read by drbg.Read and written
// by drbg.SetTestingReader without synchronization.
//
// Evidence: from one goroutine repeatedly toggle drbg.SetTestingReader
// between two distinct readers; from another call drbg.Read. Both readers
// are observed by Read (counter > 0 on each), proving that Read samples the
// unsynchronized testingReader global concurrently with the writer. With a
// happens-before edge (mutex/atomic), this would still happen, but the
// counter on each reader would always agree with the writer's last call.
// The race detector flags it through the cryptotest -> drbg path; see the
// companion crypto/rand_test.TestPoCDRBGRace.

//go:build !fips140v1.0

package fipstest

import (
	"crypto/internal/fips140/drbg"
	"sync"
	"sync/atomic"
	"testing"
)

type pocCountReader struct{ n atomic.Uint64 }

func (r *pocCountReader) Read(p []byte) (int, error) {
	r.n.Add(1)
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestPoCDRBGUnsynchronizedReader(t *testing.T) {
	var a, b pocCountReader

	var wg sync.WaitGroup
	wg.Add(2)

	stop := make(chan struct{})

	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				drbg.SetTestingReader(nil)
				return
			default:
			}
			if i&1 == 0 {
				drbg.SetTestingReader(&a)
			} else {
				drbg.SetTestingReader(&b)
			}
		}
	}()

	go func() {
		defer wg.Done()
		var buf [16]byte
		for i := 0; i < 200000; i++ {
			drbg.Read(buf[:])
		}
		close(stop)
	}()

	wg.Wait()

	t.Logf("reader a observed by drbg.Read %d times", a.n.Load())
	t.Logf("reader b observed by drbg.Read %d times", b.n.Load())
	if a.n.Load() == 0 || b.n.Load() == 0 {
		t.Fatalf("EXPECTED both readers to be picked up by concurrent drbg.Read")
	}
	t.Log("BUG REPRODUCED: drbg.Read sampled the unsynchronized testingReader global")
	t.Log("with no synchronization between writer and reader goroutines.")
}
