package nodepresence

import (
	"crypto/sha256"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func capabilitySnapshot(t *testing.T, version string) ([]byte, []byte) {
	t.Helper()
	snapshot, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.AgentCapabilities{
		AgentVersion: "1.0.35", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64",
		OpenrestyVersion: version,
		Features:         []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	return snapshot, digest[:]
}

func TestSessionOpenRestyVersion(t *testing.T) {
	snapshot, digest := capabilitySnapshot(t, "1.31.1.1")
	if got := sessionOpenRestyVersion(snapshot, digest); got == nil || *got != "1.31.1.1" {
		t.Fatalf("version = %v", got)
	}
	// No session row (LEFT JOIN), a digest mismatch, a corrupt snapshot or a
	// session that declared no OpenResty version: nothing is shown.
	if got := sessionOpenRestyVersion(nil, nil); got != nil {
		t.Fatalf("missing session = %q", *got)
	}
	wrong := append([]byte(nil), digest...)
	wrong[0] ^= 1
	if got := sessionOpenRestyVersion(snapshot, wrong); got != nil {
		t.Fatalf("digest mismatch = %q", *got)
	}
	corrupt := []byte{0xff, 0xff, 0xff}
	corruptDigest := sha256.Sum256(corrupt)
	if got := sessionOpenRestyVersion(corrupt, corruptDigest[:]); got != nil {
		t.Fatalf("corrupt snapshot = %q", *got)
	}
	for _, version := range []string{"", " 1.31.1.1", "1.31\n", strings.Repeat("1", 129)} {
		snapshot, digest := capabilitySnapshot(t, version)
		if got := sessionOpenRestyVersion(snapshot, digest); got != nil {
			t.Fatalf("version %q shown as %q", version, *got)
		}
	}
}
