// PoC for finding 014 — QUICConn.Start sets `started=true` before validating
// MinVersion. If the MinVersion check fails the second corrected attempt on
// the same QUICConn is rejected with "Start called more than once".
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

func main() {
	cfg := &tls.QUICConfig{
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}
	q := tls.QUICClient(cfg)

	err1 := q.Start(context.Background())
	fmt.Printf("first  Start (MinVersion=TLS1.2): %v\n", err1)

	cfg.TLSConfig.MinVersion = tls.VersionTLS13
	err2 := q.Start(context.Background())
	fmt.Printf("second Start (MinVersion=TLS1.3): %v\n", err2)

	if err2 != nil && strings.Contains(err2.Error(), "more than once") {
		fmt.Println()
		fmt.Println("BUG REPRODUCED: a MinVersion configuration error on the first Start")
		fmt.Println("permanently blocks the connection — the corrected retry is refused as")
		fmt.Println("if Start had already succeeded.")
		os.Exit(0)
	}
	fmt.Println("did not observe expected error pattern")
	os.Exit(1)
}
