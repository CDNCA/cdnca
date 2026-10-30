package main

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

type nativeUpgradePreflightExpectation struct {
	InstallationID string
	Version        string
	SourceCommit   string
	SourceTree     string
	ArtifactSHA256 string
	RunnerSHA256   string
}

func parseNativeUpgradePreflightArgs(args []string) (nativeUpgradePreflightExpectation, error) {
	var expected nativeUpgradePreflightExpectation
	invalid := errors.New("invalid native upgrade preflight arguments")
	values := map[string]*string{
		"--installation-id": &expected.InstallationID, "--version": &expected.Version,
		"--source-commit": &expected.SourceCommit, "--source-tree": &expected.SourceTree,
		"--artifact-sha256": &expected.ArtifactSHA256, "--runner-sha256": &expected.RunnerSHA256,
	}
	seen := make(map[string]bool, len(values))
	for index := 0; index < len(args); index++ {
		name, value, joined := strings.Cut(args[index], "=")
		target, known := values[name]
		if !known || seen[name] {
			return nativeUpgradePreflightExpectation{}, invalid
		}
		if !joined {
			index++
			if index == len(args) {
				return nativeUpgradePreflightExpectation{}, invalid
			}
			value = args[index]
		}
		if value == "" {
			return nativeUpgradePreflightExpectation{}, invalid
		}
		*target, seen[name] = value, true
	}
	installationID, err := uuid.Parse(expected.InstallationID)
	if len(seen) != len(values) || err != nil || installationID == uuid.Nil || installationID.String() != expected.InstallationID ||
		!regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`).MatchString(expected.Version) {
		return nativeUpgradePreflightExpectation{}, invalid
	}
	hex := regexp.MustCompile(`^[0-9a-f]+$`)
	for _, field := range []struct {
		value string
		size  int
	}{{expected.SourceCommit, 40}, {expected.SourceTree, 40}, {expected.ArtifactSHA256, 64}, {expected.RunnerSHA256, 64}} {
		if len(field.value) != field.size || !hex.MatchString(field.value) {
			return nativeUpgradePreflightExpectation{}, invalid
		}
	}
	return expected, nil
}

func verifyNativeUpgradePreflightStatus(status controlplaneupgrade.NativeStandaloneStatus, expected nativeUpgradePreflightExpectation) error {
	if status.Schema != controlplaneupgrade.NativeStatusSchema || !status.Ready || status.Reason != "ready" ||
		status.Phase != "idle" || status.Busy || status.ProtocolVersion != 1 ||
		(status.ArtifactFormat != controlplaneupgrade.NativeManifestSchema && status.ArtifactFormat != controlplaneupgrade.NativeManifestSignedSchema) ||
		status.InstallationID != expected.InstallationID || status.CurrentVersion != expected.Version ||
		status.SourceCommit != expected.SourceCommit || status.SourceTree != expected.SourceTree ||
		status.CurrentArtifactSHA256 != expected.ArtifactSHA256 || status.RunnerExeSHA256 != expected.RunnerSHA256 {
		return errors.New("native upgrade runner does not match the ready release")
	}
	return nil
}

func runVerifyNativeUpgradePreflight(args []string) error {
	expected, err := parseNativeUpgradePreflightArgs(args)
	if err != nil {
		return err
	}
	status, err := controlplaneupgrade.ReadNativeStandaloneStatus("/run/cdnca-upgrade/status.json", expected.InstallationID, time.Now())
	if err != nil {
		return errors.New("native upgrade runner status is unconfirmed")
	}
	return verifyNativeUpgradePreflightStatus(status, expected)
}
