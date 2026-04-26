// PoC for finding 018: SecPolicyCreateSSL NULL return reported as
// OSStatus error code 0.
//
// The unpatched code in src/crypto/x509/internal/macos/security.go:75-79 is:
//
//	ret := syscall(... SecPolicyCreateSSL ...)
//	if ret == 0 {
//	    return 0, OSStatus{"SecPolicyCreateSSL", int32(ret)}
//	}
//
// where `ret` is the returned CFRef value, and OSStatus.Error() formats as:
//
//	s.call + " error: " + strconv.Itoa(int(s.status))
//
// Because `ret` is the CF pointer (zero on NULL), it is fed back as the
// OSStatus code. The resulting non-nil error renders as "error: 0", but
// OSStatus 0 conventionally means success.
//
// This PoC reconstructs the OSStatus type identically to the package and
// shows the error string the unpatched failure path produces.
package main

import (
	"fmt"
	"strconv"
)

// Identical to crypto/x509/internal/macos.OSStatus.
type OSStatus struct {
	call   string
	status int32
}

func (s OSStatus) Error() string {
	return s.call + " error: " + strconv.Itoa(int(s.status))
}

func main() {
	// Simulate ret == 0 (NULL CFRef from SecPolicyCreateSSL).
	const ret uintptr = 0
	bug := OSStatus{call: "SecPolicyCreateSSL", status: int32(ret)}

	fmt.Println("EXPECTED: failure error not formatted as OSStatus code 0")
	fmt.Println("GOT:     ", bug.Error())
	fmt.Println()
	fmt.Println("Reference: src/crypto/x509/internal/macos/security.go:75-79 (Go master)")
	fmt.Println("OSStatus 0 conventionally means success, so this misclassifies")
	fmt.Println("a NULL CFRef failure as an OSStatus zero-success status code.")
}
