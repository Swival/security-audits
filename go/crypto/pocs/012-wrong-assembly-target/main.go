// PoC for finding 012 — wrong generated assembly target in AES amd64 generator.
//
// crypto/internal/fips140/aes/_asm/standard/aes_amd64.go drives Avo with
// `//go:generate go run . -out ../../aes_amd64.s` so the generated file
// path is .../aes/aes_amd64.s, but the post-generation cleanup hands a
// different path to removePeskyUnicodeDot:
//
//	removePeskyUnicodeDot(internalFunctions, "../../asm_amd64.s")
//
// The generated file aes_amd64.s contains the stripped internal symbols
// such as `TEXT _expand_key_128<>(SB)` that the cleanup helper is meant
// to fix up, while the asm_amd64.s path the helper is given does not
// exist in the tree at all. As a result, an actual `go generate` run
// reaches the cleanup step and either acts on the wrong file or panics
// because the supplied target is missing, while the freshly generated
// file is left unprocessed.
//
// This PoC reads the generator source plus the surrounding source layout
// to demonstrate the inconsistency without depending on Avo or the host
// toolchain. It exits non-zero if the generator-target / cleanup-target
// disagreement disappears.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	out, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "VERSION"))
	if err == nil && len(out) > 0 {
		_ = out
	}
	return runtime.GOROOT()
}

var (
	reGenerate = regexp.MustCompile(`//go:generate\s+go\s+run\s+\.\s+-out\s+(\S+)`)
	reCleanup  = regexp.MustCompile(`removePeskyUnicodeDot\([^,]+,\s*"([^"]+)"\)`)
)

func main() {
	root := goroot()
	gen := filepath.Join(root, "src", "crypto", "internal", "fips140", "aes", "_asm", "standard", "aes_amd64.go")
	src, err := os.ReadFile(gen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", gen, err)
		os.Exit(2)
	}

	mGen := reGenerate.FindStringSubmatch(string(src))
	mClean := reCleanup.FindStringSubmatch(string(src))
	if mGen == nil || mClean == nil {
		fmt.Fprintln(os.Stderr, "generator or cleanup directive not found")
		os.Exit(2)
	}
	genTarget := mGen[1]
	cleanTarget := mClean[1]

	fmt.Printf("source: %s\n", gen)
	fmt.Printf("  go:generate emits to:        %s\n", genTarget)
	fmt.Printf("  removePeskyUnicodeDot fixes: %s\n", cleanTarget)

	pkgDir := filepath.Join(root, "src", "crypto", "internal", "fips140", "aes")
	genAbs := filepath.Clean(filepath.Join(pkgDir, "_asm", "standard", genTarget))
	cleanAbs := filepath.Clean(filepath.Join(pkgDir, "_asm", "standard", cleanTarget))

	genExists := fileExists(genAbs)
	cleanExists := fileExists(cleanAbs)

	fmt.Printf("\nresolved paths:\n")
	fmt.Printf("  generator output target = %s (exists: %v)\n", genAbs, genExists)
	fmt.Printf("  cleanup target          = %s (exists: %v)\n", cleanAbs, cleanExists)

	if filepath.Base(genTarget) == filepath.Base(cleanTarget) {
		fmt.Println("\nGenerator and cleanup agree — bug not present.")
		os.Exit(1)
	}
	fmt.Printf("\nMISMATCH: generator writes %q but cleanup is run on %q.\n",
		filepath.Base(genTarget), filepath.Base(cleanTarget))

	if cleanExists {
		fmt.Println("Note: cleanup target also exists, so the helper acts on the wrong file.")
	} else {
		fmt.Println("Note: cleanup target does not exist, so a real `go generate` run will")
		fmt.Println("either fail in the cleanup step or silently leave the freshly-generated")
		fmt.Println("file with its un-stripped Unicode-dot internal TEXT symbols.")
	}

	if genExists {
		stripped, err := os.ReadFile(genAbs)
		if err == nil && strings.Contains(string(stripped), "TEXT _expand_key_128<>(SB)") {
			fmt.Println()
			fmt.Println("Confirmed: the generated file already contains an internal TEXT symbol")
			fmt.Println("that has been stripped of its Unicode dot, proving aes_amd64.s is the")
			fmt.Println("intended cleanup target rather than the asm_amd64.s named in source.")
		}
	}
	os.Exit(0)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
