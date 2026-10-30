package eventspool

import (
	"encoding/json"
	"testing"
)

const obs06CaptureDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOBS06CapturePolicyIdentitySurvivesSanitizedPublication(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{"Authorization": "Bearer secret"}
	parsed, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{
		Enabled: true, RequestHeaders: []string{"Authorization"},
	}, TrustedIdentity{
		EnrollmentNodeID: event.NodeID, TenantID: event.TenantID, SiteID: event.SiteID,
		ConfigVersionID: event.ConfigVersionID, CapturePolicyRevision: 7, CapturePolicyDigest: obs06CaptureDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CapturePolicyRevision != 7 || parsed.CapturePolicyDigest != obs06CaptureDigest ||
		parsed.RequestHeaders["Authorization"] != redactedValue {
		t.Fatalf("sanitized active policy identity = %+v", parsed)
	}
	parsed.EventID, parsed.Sequence = "event_obs06_identity", 1
	record := recordForPublicationIdentity(parsed)
	publication, err := encodePublication([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Events []struct {
			CapturePolicyRevision uint64 `json:"capture_policy_revision"`
			CapturePolicyDigest   string `json:"capture_policy_digest"`
		} `json:"events"`
	}
	if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Events) != 1 || envelope.Events[0].CapturePolicyRevision != 7 ||
		envelope.Events[0].CapturePolicyDigest != obs06CaptureDigest || !ValidPublicationMessageID(publication) {
		t.Fatalf("publication policy identity = %+v", envelope)
	}
}

func TestOBS06CapturePolicyIdentityRejectsMalformedDigest(t *testing.T) {
	event := sourceAccess(tenantOne)
	_, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{}, TrustedIdentity{
		EnrollmentNodeID: event.NodeID, TenantID: event.TenantID, SiteID: event.SiteID,
		ConfigVersionID: event.ConfigVersionID, CapturePolicyRevision: 7, CapturePolicyDigest: "SECRET",
	})
	if err == nil {
		t.Fatal("malformed active capture policy identity was accepted")
	}
}
