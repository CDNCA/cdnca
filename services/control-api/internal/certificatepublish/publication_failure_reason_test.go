package certificatepublish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

// node-logs 10-31（node-e2e D1）：目标校验拒绝（节点未承载租户等）原先一律
// publication_unavailable 无限重试、不留原因。现在原因码+节点 ID 进
// failure_code，校验类拒绝直接终态，暂时性拒绝保留有上限重试，并写结构化日志。
func TestPublisherAdapterKeepsTargetRejectionReason(t *testing.T) {
	nodeID := uuid.MustParse("0190f2a4-7b1c-7d2e-8f00-000000000078")
	for _, test := range []struct {
		name        string
		err         error
		wantOutcome certificateasset.PublicationOutcome
		wantCode    string
		wantNode    string
	}{
		{
			name: "node not carried",
			err: fmt.Errorf("resolve certificate publication target: %w", &edgeautopublish.CertificateTargetRejection{
				Code: edgeautopublish.CertificateTargetNodeNotCarried, NodeID: nodeID}),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "target_node_not_carried." + nodeID.String(), wantNode: nodeID.String(),
		},
		{
			name: "capability missing",
			err: fmt.Errorf("resolve certificate publication target: %w", &edgeautopublish.CertificateTargetRejection{
				Code: edgeautopublish.CertificateTargetNodeCapabilityAbsent, NodeID: nodeID}),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "target_node_capability_missing." + nodeID.String(), wantNode: nodeID.String(),
		},
		{
			name: "node offline",
			err: fmt.Errorf("resolve certificate publication target: %w", &edgeautopublish.CertificateTargetRejection{
				Code: edgeautopublish.CertificateTargetNodeOffline, NodeID: nodeID, Transient: true}),
			wantOutcome: certificateasset.PublicationRetry,
			wantCode:    "target_node_offline." + nodeID.String(), wantNode: nodeID.String(),
		},
		{
			name: "policy not automatic",
			err: fmt.Errorf("resolve certificate publication target: %w", &edgeautopublish.CertificateTargetRejection{
				Code: edgeautopublish.CertificateTargetPolicyNotAutomatic}),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "target_policy_not_automatic",
		},
		{
			name:        "other target validation",
			err:         fmt.Errorf("resolve certificate publication target: %w", edgeautopublish.ErrInvalidInput),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "target_invalid",
		},
		{
			// demo-fill 11-01: racing the site's own publication
			name:        "node busy with another deployment",
			err:         fmt.Errorf("resolve and persist node deployment: %w", edgedeployment.ErrNodeDeploymentActive),
			wantOutcome: certificateasset.PublicationRetry,
			wantCode:    certificateasset.PublicationFailureNodeBusy,
		},
		{
			name:        "dependency unavailable stays retryable",
			err:         fmt.Errorf("resolve target: %w", edgedeployment.ErrUnavailable),
			wantOutcome: certificateasset.PublicationRetry,
			wantCode:    "publication_unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			service := &resolverErrorPublicationService{}
			adapter, err := NewPublisherAdapter(service, resolverErrorCertificateTargetResolver{err: test.err})
			if err != nil {
				t.Fatal(err)
			}
			command := certificateasset.CertificatePublicationCommandV1{
				TenantScopeID: uuid.New(), SiteID: uuid.New(), BindingRevision: 3, Operation: "publish",
			}
			result, err := adapter.Publish(t.Context(), command)
			if err != nil || result.Outcome != test.wantOutcome || result.FailureCode != test.wantCode {
				t.Fatalf("Publish() result=%+v err=%v, want %s/%s", result, err, test.wantOutcome, test.wantCode)
			}
			if service.publishCalls != 0 {
				t.Fatalf("Publish() downstream calls=%d, want 0", service.publishCalls)
			}
			// the code must be storable (certificate_publication_intent_state_facts CHECK)
			if !validStoredFailureCode(result.FailureCode) {
				t.Fatalf("failure code %q does not fit the intent failure_code column", result.FailureCode)
			}

			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &entry); err != nil {
				t.Fatalf("want one structured log line, got %q: %v", logs.String(), err)
			}
			if entry["level"] != "WARN" || entry["event"] != "certificate_publication_failed" ||
				entry["failure_code"] != test.wantCode || entry["site_id"] != command.SiteID.String() ||
				entry["tenant_scope_id"] != command.TenantScopeID.String() ||
				!strings.Contains(fmt.Sprint(entry["error"]), "resolve") {
				t.Fatalf("log entry = %v", entry)
			}
			if test.wantNode != "" && entry["node_id"] != test.wantNode {
				t.Fatalf("log node_id = %v, want %s", entry["node_id"], test.wantNode)
			}
		})
	}
}

// validStoredFailureCode mirrors migration 118's failure_code CHECK
// ^[a-z][a-z0-9._-]{0,127}$.
func validStoredFailureCode(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
