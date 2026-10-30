package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/waf"
)

func main() {
	inputPath := flag.String("input", "", "path to the source WAF policy")
	stateRoot := flag.String("state-root", "", "absolute WAF policy state directory")
	flag.Parse()
	if *inputPath == "" || *stateRoot == "" {
		fmt.Fprintln(os.Stderr, "-input and -state-root are required")
		os.Exit(2)
	}
	file, err := os.Open(*inputPath)
	if err != nil {
		fail(err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, waf.MaxPolicyBytes+1))
	closeErr := file.Close()
	if err != nil {
		fail(err)
	}
	if closeErr != nil {
		fail(closeErr)
	}
	publisher, err := waf.NewPublisher(*stateRoot)
	if err != nil {
		fail(err)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		fail(err)
	}
	fmt.Printf("policy_version=%d\nsha256=%s\ncurrent=%s\n", publication.PolicyVersion, hex.EncodeToString(publication.SHA256[:]), publication.CurrentPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
