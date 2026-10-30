package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// telemetryChecks (B9): with Config.Telemetry the runtime creates run/secagg
// (0710, worker group) before nginx starts, the flush server listens in it and
// a site with telemetry (every published site) is logged to the node-level access log.
func telemetryChecks(config dynroute.Config) {
	directory := filepath.Join(config.StateRoot, edgeskeleton.SecurityFlushDirectory)
	info, err := os.Stat(directory)
	gid := -1
	if err == nil {
		gid = int(info.Sys().(*syscall.Stat_t).Gid)
	}
	check("telemetry-secagg-dir", err == nil && info.IsDir() && info.Mode().Perm() == 0o710 && gid == config.WorkerGID,
		"%s %v gid %d (want 0710 gid %d)", directory, modeOf(info), gid, config.WorkerGID)
	socket, err := os.Stat(filepath.Join(config.StateRoot, edgeskeleton.SecurityFlushSocket))
	check("telemetry-secagg-socket", err == nil && socket.Mode()&os.ModeSocket != 0, "%v %v", modeOf(socket), err)
	access, security := edgeconfig.DynamicRoutingTelemetryPaths(config.SharedRoot)
	// shop carries site telemetry: its request is logged (nginx writes the
	// line in the log phase, after the response)
	served := get(portPlain, "shop.d13.test", "/telemetry")
	time.Sleep(300 * time.Millisecond)
	content, _ := os.ReadFile(access)
	check("telemetry-access-line", served.status == 200 && strings.Contains(string(content), "/telemetry"),
		"%d %d bytes", served.status, len(content))
	accessInfo, accessErr := os.Stat(access)
	securityInfo, securityErr := os.Stat(security)
	check("telemetry-node-logs", accessErr == nil && securityErr == nil && accessInfo.Size() > 0 &&
		accessInfo.Mode().Perm() == 0o600 && securityInfo.Mode().Perm() == 0o600,
		"access %v %v security %v %v", modeOf(accessInfo), accessErr, modeOf(securityInfo), securityErr)
}

func modeOf(info os.FileInfo) any {
	if info == nil {
		return nil
	}
	return []any{info.Mode(), info.Size()}
}
