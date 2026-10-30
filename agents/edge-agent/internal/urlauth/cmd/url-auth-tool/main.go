package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "publish":
		publish(os.Args[2:])
	case "sign":
		sign(os.Args[2:])
	default:
		usage()
	}
}

func publish(arguments []string) {
	flags := flag.NewFlagSet("publish", flag.ExitOnError)
	root := flags.String("root", "", "absolute URL auth policy state directory")
	_ = flags.Parse(arguments)
	if *root == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: url-auth-tool publish -root /absolute/path < policy.json")
		os.Exit(2)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, urlauth.MaxPolicyBytes+1))
	if err != nil {
		fatal("read policy", err)
	}
	publisher, err := urlauth.NewPublisher(*root)
	if err != nil {
		fatal("create publisher", err)
	}
	publication, err := publisher.PublishJSON(raw)
	if err != nil {
		fatal("publish policy", err)
	}
	fmt.Printf("policy_version=%d sha256=%x current=%s\n", publication.PolicyVersion, publication.SHA256, publication.CurrentPath)
}

func sign(arguments []string) {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	policyPath := flags.String("policy", "", "compiled policy path")
	method := flags.String("method", "GET", "uppercase HTTP method")
	target := flags.String("target", "", "unsigned request target")
	keyID := flags.String("key-id", "", "current key by default, or configured previous key")
	clientIP := flags.String("client-ip", "", "client address when IP binding is enabled")
	expiresAt := flags.Int64("expires-at", 0, "absolute Unix expiration time")
	nowUnix := flags.Int64("now", 0, "Unix signing time; current time by default")
	_ = flags.Parse(arguments)
	if *policyPath == "" || *target == "" || *expiresAt == 0 || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: url-auth-tool sign -policy /path/current.json -target /path -expires-at UNIX_SECONDS [-client-ip IP] [-key-id ID]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		fatal("read compiled policy", err)
	}
	policy, err := urlauth.LoadCompiledJSON(raw)
	if err != nil {
		fatal("load compiled policy", err)
	}
	now := time.Now()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0)
	}
	signed, err := urlauth.SignTargetAt(policy, *method, *target, *keyID, *clientIP, time.Unix(*expiresAt, 0), now)
	if err != nil {
		fatal("sign target", err)
	}
	fmt.Println(signed)
}

func fatal(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", operation, err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: url-auth-tool <publish|sign> [options]")
	os.Exit(2)
}
