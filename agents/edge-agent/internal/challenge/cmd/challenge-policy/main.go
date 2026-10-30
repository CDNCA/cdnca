package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
)

func main() {
	root := flag.String("root", "", "absolute challenge policy state directory")
	flag.Parse()
	if *root == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: challenge-policy -root /absolute/path < policy.json")
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, challenge.MaxPolicyBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policy: %v\n", err)
		os.Exit(1)
	}
	publisher, err := challenge.NewPublisher(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("policy_version=%d sha256=%x current=%s\n", publication.PolicyVersion, publication.SHA256, publication.CurrentPath)
}
