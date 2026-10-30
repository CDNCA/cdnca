package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachefreshness"
)

func main() {
	stateRoot := flag.String("state-root", "", "absolute cache freshness runtime state root")
	luaRoot := flag.String("lua-root", "", "absolute cache freshness Lua root")
	flag.Parse()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, cachefreshness.MaxPolicyBytes+1))
	if err != nil {
		fatal(err)
	}
	artifact, err := cachefreshness.CompileJSON(raw, cachefreshness.RuntimePaths{StateRoot: *stateRoot, LuaRoot: *luaRoot})
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stdout.Write(artifact.Nginx); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
