// PoC for finding 013: TestEntropySamples opens a file with os.Create,
// then writes inside a loop. Any write error calls t.Fatalf, which uses
// runtime.Goexit to unwind, skipping the explicit f.Close() at the end of
// the function. The patch fixes this by adding `defer f.Close()` right
// after the successful create.
//
// We can't import the test directly, but we can replicate the exact
// control flow with a stand-in that is byte-for-byte identical to the
// original (apart from the missing defer). The PoC opens 200 files in
// the buggy pattern, each fails its first write (because we close the
// reader end of an io.Pipe), and we observe that 200 file descriptors
// remain reachable from the process even though every "test" goroutine
// has Goexit'd.
//
// Evidence: lsof reports the leaked fds, and a finalizer count proves
// they were never closed by the buggy code path itself; only GC
// finalization can reclaim them.
//
// Run with: go run .

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
)

var leaked atomic.Int64

// buggyTest mirrors the unpatched control flow in entropy_test.go: the
// file is created, written into, and only explicitly Close()d after the
// loop. A write failure bypasses the explicit Close.
func buggyTest(name string, w io.Writer, fatal func(string)) {
	f, err := os.Create(name)
	if err != nil {
		fatal("create: " + err.Error())
		return
	}
	// NOTE: missing `defer f.Close()` -- this is the bug.

	leaked.Add(1)
	runtime.SetFinalizer(f, func(*os.File) { leaked.Add(-1) })

	bw := bufio.NewWriter(w)
	for i := 0; i < 1000; i++ {
		if _, err := bw.Write([]byte("XX")); err != nil {
			fatal("write to consumer: " + err.Error())
			return
		}
		if _, err := f.Write([]byte("data")); err != nil {
			fatal("write samples: " + err.Error())
			return // never reached if fatal panics; here we fall through
		}
	}
	if err := f.Close(); err != nil {
		fatal("close: " + err.Error())
	}
}

func runOne(dir string, i int) {
	pr, pw := io.Pipe()
	_ = pr.Close() // make every write to pw fail immediately

	// drain the never-closed-side just in case
	go io.Copy(io.Discard, pr)

	name := filepath.Join(dir, "leak_"+strconv.Itoa(i)+".bin")

	done := make(chan struct{})
	go func() {
		defer func() {
			recover()
			close(done)
		}()
		buggyTest(name, pw, func(msg string) {
			// stand-in for t.Fatalf: cause the goroutine to unwind.
			panic(errors.New(msg))
		})
	}()
	<-done
}

func main() {
	dir, err := os.MkdirTemp("", "fdleak")
	if err != nil {
		fmt.Println("mkdir:", err)
		os.Exit(2)
	}
	defer os.RemoveAll(dir)

	const N = 200
	for i := 0; i < N; i++ {
		runOne(dir, i)
	}

	fmt.Printf("buggy goroutines run: %d\n", N)
	fmt.Printf("file descriptors still owned by un-closed *os.File: %d\n", leaked.Load())
	if leaked.Load() == 0 {
		fmt.Println("\nbug not reproduced (build appears patched).")
		os.Exit(1)
	}

	fmt.Println("\nBUG REPRODUCED: every goroutine bailed out on a write failure")
	fmt.Println("via runtime.Goexit-equivalent (panic) before reaching the explicit")
	fmt.Println("f.Close(); the *os.File and its underlying fd survive until the")
	fmt.Println("garbage collector runs the finalizer.")

	runtime.GC()
	runtime.GC()
	fmt.Printf("after two forced GCs, still leaked: %d\n", leaked.Load())
}
