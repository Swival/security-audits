// PoC for finding 022: drbg.testingReader is read by drbg.Read and written
// by drbg.SetTestingReader without synchronization.
//
// The crypto/internal/rand.SetTestingReader linkname (used by
// testing/cryptotest) ultimately writes drbg.testingReader. Calling it
// concurrently with crypto/rand.Read (which calls drbg.Read in the default
// path) reads and writes the same global without a mutex, and the race
// detector reports it.
//
// Evidence: `go test -race -run TestPoCDRBGRace` reports DATA RACE on
// crypto/rand.Reader (the proxy through which drbg.Read is reached) with
// the writer happening inside SetGlobalRandom -> drbg.SetTestingReader.

package rand_test

import (
	cryptorand "crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"testing/cryptotest"
)

func TestPoCDRBGRace(t *testing.T) {
	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		var b [16]byte
		for !stop.Load() {
			cryptorand.Read(b[:])
		}
	}()

	for i := 0; i < 200; i++ {
		cryptotest.SetGlobalRandom(t, uint64(i))
	}
	stop.Store(true)
	wg.Wait()
}
