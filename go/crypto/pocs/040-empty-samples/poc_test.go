// PoC for finding 040: RepetitionCountTest panics on empty samples.
//
// Evidence: passing nil or []uint8{} reaches `samples[0]` before any
// length check and triggers an out-of-range runtime panic instead of
// returning nil.

package entropy

import (
	"runtime"
	"strings"
	"testing"
)

func TestPoCEmptySamplesPanic(t *testing.T) {
	for _, name := range []string{"nil", "empty"} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s: EXPECTED a runtime panic from samples[0]; GOT no panic", name)
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
				if !strings.Contains(msg, "out of range") && !strings.Contains(msg, "index out of range") {
					t.Logf("%s: recovered non-bounds panic: %v", name, r)
				}
				_, file, line, _ := runtime.Caller(0)
				t.Logf("%s: BUG REPRODUCED at %s:%d -- recovered panic: %v", name, file, line, r)
			}()
			var samples []uint8
			if name == "empty" {
				samples = []uint8{}
			}
			err := RepetitionCountTest(samples)
			t.Fatalf("%s: EXPECTED a panic; GOT err=%v", name, err)
		})
	}
}
