package certificatepublish

import (
	"os"
	"strings"
	"testing"
)

func TestCertificatePublicationFreezesIdentityAndUnpublishSkipsTargetResolution48(t *testing.T) {
	body, err := os.ReadFile("publication_adapter.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `if command.Operation == "unpublish"`) {
		t.Fatal("unpublish must branch before automatic target resolution")
	}
	branch := strings.Index(text, `if command.Operation == "unpublish"`)
	resolver := strings.Index(text, "policy, err := adapter.resolver.ResolveCertificateTarget")
	if resolver >= 0 && resolver < branch {
		t.Fatal("unpublish resolves current target policy before historical source")
	}
	for _, required := range []string{"AssetID: command.AssetID", "VersionID: command.VersionID", "BindingRevision: command.BindingRevision", "Deadline: command.Deadline"} {
		if !strings.Contains(text, required) {
			t.Errorf("adapter missing frozen intent field %q", required)
		}
	}
}

func TestCertificateDeploymentAPIIsPermissionAndSourceSpecialized48(t *testing.T) {
	body, err := os.ReadFile("../edgedeployment/certificate_publisher.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{"additionalPermissions", "source SecretRolloutSource"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("certificate deployment API exposes generic caller control %q", forbidden)
		}
	}
	for _, required := range []string{"certificateManagePermission", "certificateGeneratorName", "CertificateSecretRolloutSource"} {
		if !strings.Contains(text, required) {
			t.Errorf("certificate deployment API missing fixed contract %q", required)
		}
	}
}
