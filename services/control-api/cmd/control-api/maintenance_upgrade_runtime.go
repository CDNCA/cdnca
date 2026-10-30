package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

// These values are set together with controlVersion by the immutable release
// build. Runtime environment variables and deployment history are not sources.
var controlSourceCommit, controlSourceTree, controlBuildTime string

var controlGitObjectPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func configureMaintenanceUpgradeRuntime(status *controlupgrade.MaintenanceRuntime, handler controlPlaneUpgradeHTTPRuntime) {
	executable, err := os.Executable()
	if runtime.GOOS == "linux" {
		// Read the running inode, including while current points at another release.
		executable, err = "/proc/self/exe", nil
	}
	if err != nil {
		executable = ""
	}
	status.Build = maintenanceBuildFacts(controlSourceCommit, controlSourceTree, controlBuildTime, executable)
	if handler != nil {
		status.ControlRuntime = handler.MaintenanceRuntimeStatus
	}
}

func maintenanceBuildFacts(commit, tree, builtAt, executable string) *controlupgrade.MaintenanceBuild {
	facts := &controlupgrade.MaintenanceBuild{}
	if controlGitObjectPattern.MatchString(commit) {
		facts.SourceCommit = &commit
	}
	if controlGitObjectPattern.MatchString(tree) {
		facts.SourceTree = &tree
	}
	if parsed, err := time.Parse(time.RFC3339, builtAt); err == nil {
		facts.BuiltAt = &parsed
	}
	file, err := os.Open(executable)
	if err != nil {
		return facts
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<30 {
		return facts
	}
	digest := sha256.New()
	if size, err := io.Copy(digest, io.LimitReader(file, info.Size()+1)); err == nil && size == info.Size() {
		value := fmt.Sprintf("%x", digest.Sum(nil))
		facts.BinarySHA256 = &value
	}
	return facts
}
