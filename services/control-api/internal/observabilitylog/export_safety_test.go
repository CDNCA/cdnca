package observabilitylog

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOBS09ExportNeutralizesSpreadsheetFormulaCells(t *testing.T) {
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	repository := &fakeRepository09{rows: []Fact{{
		ID: "=event", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID,
		Action: "site.update", ReasonCode: "site.update", ResultCode: "success",
		ResourceType: "site", ResourceID: "+resource", RequestID: "@request",
		SourceIP: "192.0.2.1", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute),
	}}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: uuid.New(),
		Permissions: []string{"identity.self.read"}}
	artifact, err := service.Export(t.Context(), actor, Query{})
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(artifact.Content)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][0] != "'=event" || records[1][7] != "'+resource" || records[1][8] != "'@request" {
		t.Fatalf("unsafe export row = %#v", records)
	}
	digest := sha256.Sum256(artifact.Content)
	if artifact.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("artifact digest = %q, want %x", artifact.SHA256, digest)
	}
}
