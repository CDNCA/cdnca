// Command roothelperfixture stands in for edge-agent in the root helper
// end-to-end test: it answers the packaging probes exactly like the Agent and
// otherwise runs as a long-lived service. It is never shipped.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Set with -ldflags "-X main.version=... -X main.daemonExit=1".
var (
	version    = "development"
	daemonExit = ""
)

func main() {
	arguments := os.Args[1:]
	switch {
	case len(arguments) == 1 && arguments[0] == "--version":
		fmt.Printf("{\"event\":\"version\",\"agent_version\":\"%s\",\"build_id\":\"roothelperfixture\"}\n", version)
	case len(arguments) == 3 && arguments[0] == "--check-config" && arguments[1] == "-config":
		if _, err := os.ReadFile(arguments[2]); err != nil {
			os.Exit(3)
		}
	case len(arguments) == 2 && arguments[0] == "-config":
		if daemonExit != "" {
			os.Exit(1)
		}
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
		<-stop
	default:
		os.Exit(2)
	}
}
