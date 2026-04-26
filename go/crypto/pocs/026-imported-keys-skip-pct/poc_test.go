// PoC for finding 026 — NewDecapsulationKey768 (seed-import path) skips the
// FIPS 140-3 Pairwise Consistency Test that GenerateKey768 performs. Using
// the GODEBUG simulator failfipscast=ML-KEM PCT in FIPS mode, generation
// terminates the process via runtime.fatal because PCT is enforced. The
// import path returns a key successfully because PCT is never called.
//
// The test reruns itself in a subprocess with the appropriate GODEBUG so
// fips140.Enabled is true during package init.

package mlkem

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPoC026ImportedKeysSkipPCT(t *testing.T) {
	if os.Getenv("POC026_CHILD") == "" {
		runChild := func(mode string) (stdout, stderr string, exitErr error) {
			cmd := exec.Command(os.Args[0], "-test.run=TestPoC026ImportedKeysSkipPCT", "-test.v")
			cmd.Env = append(os.Environ(),
				"POC026_CHILD="+mode,
				"GODEBUG=fips140=on,failfipscast=ML-KEM PCT",
			)
			var so, se bytes.Buffer
			cmd.Stdout = &so
			cmd.Stderr = &se
			exitErr = cmd.Run()
			return so.String(), se.String(), exitErr
		}

		genStdout, genStderr, genErr := runChild("generate")
		t.Logf("generate child: err=%v", genErr)
		t.Logf("generate stdout/stderr (tail):\n%s%s", tail(genStdout), tail(genStderr))
		if genErr == nil {
			t.Fatal("generate path did NOT terminate; expected runtime.fatal from forced PCT failure")
		}
		if !strings.Contains(genStderr+genStdout, "FIPS 140-3 self-test failed: ML-KEM PCT") {
			t.Fatal("expected fatal banner from forced PCT failure in generate path")
		}

		impStdout, impStderr, impErr := runChild("import")
		t.Logf("import child: err=%v", impErr)
		t.Logf("import stdout/stderr (tail):\n%s%s", tail(impStdout), tail(impStderr))
		if impErr != nil {
			t.Fatalf("import path terminated unexpectedly: %v\n%s%s", impErr, impStderr, impStdout)
		}
		if !strings.Contains(impStdout, "POC026_OK") {
			t.Fatal("expected POC026_OK marker from import child")
		}

		t.Log("BUG REPRODUCED: GenerateKey768 invokes the ML-KEM PCT and is killed by")
		t.Log("the GODEBUG-simulated PCT failure, but NewDecapsulationKey768 (seed import)")
		t.Log("returns successfully because the PCT is never called for imported keys.")
		return
	}

	switch os.Getenv("POC026_CHILD") {
	case "generate":
		_, err := GenerateKey768()
		if err != nil {
			os.Stderr.WriteString("generate err: " + err.Error() + "\n")
			os.Exit(2)
		}
		os.Stdout.WriteString("POC026_GENERATE_FINISHED_WITHOUT_FATAL\n")
	case "import":
		var seed [SeedSize]byte
		for i := range seed {
			seed[i] = byte(i)
		}
		_, err := NewDecapsulationKey768(seed[:])
		if err != nil {
			os.Stderr.WriteString("import err: " + err.Error() + "\n")
			os.Exit(2)
		}
		os.Stdout.WriteString("POC026_OK\n")
	}
}

func tail(s string) string {
	const max = 1500
	if len(s) <= max {
		return s
	}
	return "...\n" + s[len(s)-max:]
}
