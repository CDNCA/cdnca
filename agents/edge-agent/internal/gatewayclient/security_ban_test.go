package gatewayclient

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type securityBanApplierFunc func([]byte) SecurityBanResult

func (function securityBanApplierFunc) ApplySecurityBans(encoded []byte) SecurityBanResult { return function(encoded) }

// The status binds the command (event, revision, digest); a refused snapshot
// carries its error code, an Agent without an applier answers not_supported.
func TestSecurityBanStatusBindsTheCommand(t *testing.T) {
	nodeID := "11111111-1111-4111-8111-111111111111"
	body := []byte(`{"list":1}`)
	digest := sha256.Sum256(body)
	command := &agentv1.SecurityBanCommand{Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(),
		OccurredTime: timestamppb.Now()}, NodeId: nodeID, Revision: 7, ListJson: body, ListSha256: digest[:]}
	client := &Client{config: Config{NodeID: nodeID}}
	report, err := client.securityBanStatus(command, time.Now())
	if err != nil || report.Applied || report.ErrorCode != securityban.ErrorNotSupported {
		t.Fatalf("no applier = %+v %v", report, err)
	}
	client.securityBans = securityBanApplierFunc(func(encoded []byte) SecurityBanResult {
		if string(encoded) != string(body) {
			t.Fatalf("applier got %q", encoded)
		}
		return SecurityBanResult{Applied: true, Bans: 3, Releases: 1}
	})
	report, err = client.securityBanStatus(command, time.Now())
	if err != nil || !report.Applied || report.ErrorCode != "" || report.Bans != 3 || report.Releases != 1 ||
		report.CommandEventId != command.Event.EventId || report.Revision != 7 || string(report.ListSha256) != string(digest[:]) {
		t.Fatalf("applied status = %+v %v", report, err)
	}
	client.securityBans = securityBanApplierFunc(func([]byte) SecurityBanResult { return SecurityBanResult{ErrorCode: securityban.ErrorStale} })
	if report, _ = client.securityBanStatus(command, time.Now()); report.Applied || report.ErrorCode != securityban.ErrorStale {
		t.Fatalf("refused status = %+v", report)
	}
	command.ListSha256 = make([]byte, sha256.Size)
	if _, err := client.securityBanStatus(command, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("digest mismatch = %v", err)
	}
}
