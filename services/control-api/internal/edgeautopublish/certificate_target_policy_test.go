package edgeautopublish

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestCertificateTargetPolicyRequiresAutomaticHealthyEligibleNodes47(t *testing.T) {
	policy := CertificateTargetPolicy{
		PolicyRevision: 4, NodeIDs: []uuid.UUID{uuid.New()},
		RequiredCapabilities: certificatePublicationCapabilities(),
		ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
		RequiredConsecutiveSuccesses: 2, Deadline: time.Now().Add(time.Minute),
	}
	if !validCertificateTargetPolicy(policy, time.Now()) {
		t.Fatal("valid certificate target policy rejected")
	}
	for _, mutate := range []func(*CertificateTargetPolicy){
		func(value *CertificateTargetPolicy) { value.PolicyRevision = 0 },
		func(value *CertificateTargetPolicy) { value.NodeIDs = nil },
		func(value *CertificateTargetPolicy) { value.RequiredCapabilities = nil },
		func(value *CertificateTargetPolicy) { value.Deadline = time.Now().Add(-time.Second) },
	} {
		changed := policy
		mutate(&changed)
		if validCertificateTargetPolicy(changed, time.Now()) {
			t.Fatalf("invalid certificate target policy accepted: %+v", changed)
		}
	}
}

func TestCertificatePublicationCapabilitiesAreFrozenAndMinimal47(t *testing.T) {
	got := certificatePublicationCapabilities()
	if len(got) != 2 || got[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE ||
		got[0].ApiVersion != 1 || got[1].Name != agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK ||
		got[1].ApiVersion != 1 {
		t.Fatalf("certificate capabilities=%+v", got)
	}
}
