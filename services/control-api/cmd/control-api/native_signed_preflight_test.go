package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

func TestNativeUpgradePreflightSignedArtifactFormat(t *testing.T) {
	expected, _, status := nativeUpgradePreflightFixture()
	status.ArtifactFormat = controlplaneupgrade.NativeManifestSignedSchema
	if err := verifyNativeUpgradePreflightStatus(status, expected); err != nil {
		t.Fatalf("signed release preflight rejected: %v", err)
	}
	status.ArtifactFormat = "cdnca.native-management.release/v3"
	if err := verifyNativeUpgradePreflightStatus(status, expected); err == nil {
		t.Fatal("unknown provenance accepted")
	}
}
