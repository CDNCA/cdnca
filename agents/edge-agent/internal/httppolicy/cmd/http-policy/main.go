package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/httppolicy"
)

func main() {
	input := flag.String("input", "", "path to the versioned HTTP policy JSON")
	stateRoot := flag.String("state-root", "", "private HTTP policy publication directory")
	flag.Parse()
	if *input == "" || *stateRoot == "" {
		fmt.Fprintln(os.Stderr, "-input and -state-root are required")
		os.Exit(2)
	}
	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read policy failed")
		os.Exit(1)
	}
	raw, err := io.ReadAll(io.LimitReader(file, httppolicy.MaxPolicyBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "read policy failed")
		os.Exit(1)
	}
	publisher, err := httppolicy.NewPublisher(*stateRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("policy_version=%d\nsha256=%s\ncommit=%s\nversion=%s\nchanged=%t\ndurability_confirmed=%t\n",
		publication.PolicyVersion, hex.EncodeToString(publication.Digest[:]),
		publication.CommitPath, publication.VersionPath, publication.Changed,
		publication.DurabilityConfirmed)
}
