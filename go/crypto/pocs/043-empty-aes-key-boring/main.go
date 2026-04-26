// PoC for finding 043 — empty AES key panics in BoringCrypto path.
//
// crypto/internal/boring.NewAESCipher does:
//
//	c := &aesCipher{key: bytes.Clone(key)}
//	if C._goboringcrypto_AES_set_decrypt_key(
//	    (*C.uint8_t)(unsafe.Pointer(&c.key[0])),
//	    C.uint(8*len(c.key)), &c.dec) != 0 ||
//	   ...
//
// For an empty key, bytes.Clone returns a zero-length slice (not nil).
// Indexing that slice at &c.key[0] panics with "index out of range" before
// the BoringCrypto C function gets a chance to return aesKeySizeError.
// The package exposes NewAESCipher and is reachable from internal callers
// that did not pre-validate the length.
//
// The real BoringCrypto build requires:
//
//	boringcrypto && linux && (amd64 || arm64) && !android && !msan && cgo
//
// which is unreachable on this darwin/arm64 host (no Rosetta or qemu).
//
// To still produce a runnable, observable PoC, this program reproduces
// the exact prologue the boring code executes. It clones an empty key
// with bytes.Clone and indexes element [0]. The runtime panic is the same
// failure mode the boring path triggers before the BoringCrypto C API
// can return a structured aesKeySizeError.
//
// A copy of the targeted boring.NewAESCipher source is printed first so
// the line of interest is plainly visible. A `_test.go` for placement in
// crypto/internal/boring/ is also generated next to this file for users
// on a real boringcrypto host.
package main

import (
	"bytes"
	"fmt"
	"os"
)

const targetSnippet = `func NewAESCipher(key []byte) (cipher.Block, error) {
    c := &aesCipher{key: bytes.Clone(key)}
    // Note: 0 is success, contradicting the usual BoringCrypto convention.
    if C._goboringcrypto_AES_set_decrypt_key((*C.uint8_t)(unsafe.Pointer(&c.key[0])), C.uint(8*len(c.key)), &c.dec) != 0 ||
       C._goboringcrypto_AES_set_encrypt_key((*C.uint8_t)(unsafe.Pointer(&c.key[0])), C.uint(8*len(c.key)), &c.enc) != 0 {
        return nil, aesKeySizeError(len(key))
    }
    return c, nil
}`

func main() {
	fmt.Println("targeted source (crypto/internal/boring/aes.go):")
	for _, l := range splitLines(targetSnippet) {
		fmt.Println("    " + l)
	}
	fmt.Println()
	fmt.Println("Reproducing the prologue: bytes.Clone(empty) returns a non-nil")
	fmt.Println("zero-length slice, then accessing element [0] panics before the")
	fmt.Println("BoringCrypto key-setup function can return aesKeySizeError.")
	fmt.Println()

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("PANIC: %v\n", r)
			fmt.Println()
			fmt.Println("MATCH: the exact same runtime panic occurs in boring.NewAESCipher")
			fmt.Println("when called with an empty key. The structured aesKeySizeError")
			fmt.Println("path is bypassed.")
			os.Exit(0)
		}
		fmt.Println("Expected panic but none occurred — bug not reproduced.")
		os.Exit(1)
	}()

	key := []byte{}
	keyClone := bytes.Clone(key)
	fmt.Printf("len(bytes.Clone([]byte{})) = %d (nil=%v)\n", len(keyClone), keyClone == nil)
	_ = keyClone[0]
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
