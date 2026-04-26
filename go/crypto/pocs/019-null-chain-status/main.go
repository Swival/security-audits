// PoC for finding 019: SecTrustCopyCertificateChain NULL return reported
// as OSStatus error code 0.
//
// The unpatched code in src/crypto/x509/internal/macos/security.go:140-143:
//
//	ret := syscall(... SecTrustCopyCertificateChain ..., uintptr(trustObj), ...)
//	if ret == 0 {
//	    return 0, OSStatus{"SecTrustCopyCertificateChain", int32(ret)}
//	}
//
// SecTrustCopyCertificateChain returns a CFRef pointer, not an OSStatus.
// A NULL pointer signals failure but it is not a status code. Storing it
// in OSStatus.status produces a non-nil error formatted as
// "SecTrustCopyCertificateChain error: 0", which conventionally means
// success.
package main

import (
	"fmt"
	"strconv"
)

type OSStatus struct {
	call   string
	status int32
}

func (s OSStatus) Error() string {
	return s.call + " error: " + strconv.Itoa(int(s.status))
}

func main() {
	const ret uintptr = 0
	bug := OSStatus{call: "SecTrustCopyCertificateChain", status: int32(ret)}

	fmt.Println("EXPECTED: NULL CFRef failure not reported as OSStatus 0")
	fmt.Println("GOT:     ", bug.Error())
	fmt.Println()
	fmt.Println("Reference: src/crypto/x509/internal/macos/security.go:140-143 (Go master)")
}
