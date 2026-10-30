package controlplaneupgradehttp

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

func TestNativeSignedArtifactStatusPublication(t *testing.T) {
	handler, repository, request, status := nativeFixture(t)
	status.ArtifactFormat = controlplaneupgrade.NativeManifestSignedSchema
	if actual := handler.MaintenanceRuntimeStatus(t.Context()); !actual.Ready {
		t.Fatalf("v2 runner unavailable: %+v", actual)
	}
	if _, err := handler.Publish(t.Context(), request); err != nil || repository.writes != 1 {
		t.Fatalf("v2 publication: %v writes=%d", err, repository.writes)
	}
	status.ArtifactFormat = "cdnca.native-management.release/v3"
	if actual := handler.MaintenanceRuntimeStatus(t.Context()); actual.Ready {
		t.Fatalf("unknown schema ready: %+v", actual)
	}
}
