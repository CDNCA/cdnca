package main

import "os"

var behavior = "healthy"

func main() {
	mode := "start"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch {
	case behavior == "crash" && mode == "start":
		os.Exit(20)
	case behavior == "unhealthy" && mode == "health":
		os.Exit(21)
	case mode != "start" && mode != "health":
		os.Exit(22)
	}
}
