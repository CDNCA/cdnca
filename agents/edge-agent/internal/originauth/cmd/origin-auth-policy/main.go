package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/originauth"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: origin-auth-policy PUBLISH_ROOT")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, originauth.MaxPolicyBytes+1))
	if err != nil {
		return fmt.Errorf("read policy")
	}
	publisher, err := originauth.NewPublisher(os.Args[1])
	if err != nil {
		return err
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		return err
	}
	fmt.Printf("policy_version=%d\nsha256=%x\n", publication.PolicyVersion, publication.SHA256)
	return nil
}
