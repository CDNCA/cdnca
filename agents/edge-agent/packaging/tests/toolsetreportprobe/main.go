// Command toolsetreportprobe prints, as protojson, the packaging toolset
// report the production Agent puts in its heartbeat
// (EdgeRuntimeStatus.packaging_toolset), and exits 1 when agent-gateway and
// control-api would refuse it. Used by root_helper_refresh_e2e.sh.
package main

import (
	"fmt"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/packagingtoolset"
	contract "github.com/cdnca/cdnca/libs/edgeconfig/packagingtoolset"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	report := packagingtoolset.NewReporter(packagingtoolset.ProductionPaths()).Report()
	encoded, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if !contract.Valid(report.RefreshStatus, report.RefreshVersion, report.RefreshReason, report.RefreshTime != nil,
		report.HelperStatus, report.HelperReason, report.ScriptsSha256, report.HelperSha256) {
		fmt.Fprintln(os.Stderr, "report would be refused by the gateway")
		os.Exit(1)
	}
}
