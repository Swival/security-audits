// PoC for finding 041: Windows certificate verification panics when
// VerifyOptions.KeyUsages contains only EKUs that are unsupported by
// the Windows OID table (and does not include ExtKeyUsageAny).
//
// The unpatched code in src/crypto/x509/root_windows.go:217-230 reads:
//
//	oids := make([]*byte, 0, len(keyUsages))   // non-nil empty slice
//	for _, eku := range keyUsages {
//	    if eku == ExtKeyUsageAny { oids = nil; break }
//	    if oid, ok := windowsExtKeyUsageOIDs[eku]; ok {
//	        oids = append(oids, &oid[0])
//	    }
//	}
//	if oids != nil {
//	    ...
//	    para.RequestedUsage.Usage.UsageIdentifiers = &oids[0]   // panics
//	}
//
// `make([]*byte, 0, n)` is non-nil. If every requested EKU is missing from
// windowsExtKeyUsageOIDs, the slice stays empty but non-nil, the `oids != nil`
// branch is taken, and indexing `&oids[0]` panics with "index out of range".
//
// We faithfully reproduce that pattern here. The PoC panics with a stack
// trace from `&oids[0]` on an empty slice, exactly the way root_windows.go
// would.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

// Mock crypto/x509.ExtKeyUsage. The exact integer values do not matter —
// the bug is that the windowsExtKeyUsageOIDs map lookup can miss for any
// caller-supplied EKU value not present in the table.
type ExtKeyUsage int

const (
	ExtKeyUsageAny        ExtKeyUsage = 0
	ExtKeyUsageServerAuth ExtKeyUsage = 1
)

// Map mirrors crypto/x509/root_windows.go windowsExtKeyUsageOIDs, populated
// from extKeyUsageOIDs at init. Any caller-supplied EKU integer that does
// not appear here goes through the missing-OID branch.
var windowsExtKeyUsageOIDs = map[ExtKeyUsage][]byte{
	ExtKeyUsageServerAuth: []byte("1.3.6.1.5.5.7.3.1\x00"),
}

// Caller can pass any int; e.g. a future ExtKeyUsage constant or simply
// an unrecognized integer. windowsExtKeyUsageOIDs[unknownEKU] returns
// (zero, false), so nothing is appended to oids.
const unknownEKU ExtKeyUsage = 999

type para struct {
	Length          uint32
	UsageIdentifier *byte
}

// systemVerifyMimic reproduces root_windows.go:213-235 verbatim (in spirit)
// for the panic path.
func systemVerifyMimic(keyUsages []ExtKeyUsage) {
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	oids := make([]*byte, 0, len(keyUsages))
	for _, eku := range keyUsages {
		if eku == ExtKeyUsageAny {
			oids = nil
			break
		}
		if oid, ok := windowsExtKeyUsageOIDs[eku]; ok {
			oids = append(oids, &oid[0])
		}
	}
	var p para
	if oids != nil {
		p.Length = uint32(len(oids))
		p.UsageIdentifier = oids[0] // <-- &oids[0] in the real code; same panic
	}
	_ = p
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("PANIC:", r)
			fmt.Println()
			fmt.Println("Stack:")
			fmt.Println(string(debug.Stack()))
			fmt.Println("BUG REPRODUCED: empty-but-non-nil oids slice indexed at oids[0].")
			os.Exit(0)
		}
	}()

	// Caller supplies only unsupported EKUs without ExtKeyUsageAny.
	keyUsages := []ExtKeyUsage{unknownEKU}

	fmt.Println("Calling systemVerify with only-unsupported EKUs:", keyUsages)
	systemVerifyMimic(keyUsages)
	fmt.Println("UNEXPECTED: no panic; bug not reproduced")
	os.Exit(2)
}
