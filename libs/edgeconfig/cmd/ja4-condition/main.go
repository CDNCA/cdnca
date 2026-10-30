// ja4-condition prints the Lua condition the security state machine renders
// for a WAF rule on the given JA4 fingerprints (scripts/security/ja4-smoke.sh).
package main

import (
	"fmt"
	"os"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func main() {
	values, err := edgeconfig.NormalizeWAFJA4(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage: ja4-condition JA4...")
		os.Exit(2)
	}
	fmt.Println(edgeconfig.RenderWAFJA4Condition(values))
}
