package qualitydiagnostics

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

func TestNewRuntimeServiceFailsClosedForAuthorityAndCursorKeyConfiguration(t *testing.T) {
	validAuthority := &finalizedAuthorityStub{}
	validKey := bytes.Repeat([]byte{0x42}, 32)
	var typedNil *finalizedAuthorityStub
	tests := []struct {
		name      string
		authority FinalizedLatestStateAuthority
		cursorKey []byte
	}{
		{name: "nil authority", cursorKey: validKey},
		{name: "typed nil authority", authority: typedNil, cursorKey: validKey},
		{name: "missing key", authority: validAuthority},
		{name: "short key", authority: validAuthority, cursorKey: bytes.Repeat([]byte{0x42}, 31)},
		{name: "oversized key", authority: validAuthority, cursorKey: bytes.Repeat([]byte{0x42}, 129)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewRuntimeService(RuntimeConfig{CursorKey: test.cursorKey}, RuntimeDependencies{
				Authority: test.authority,
			})
			if service != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewRuntimeService() = %#v, %v", service, err)
			}
		})
	}
}

func TestNewRuntimeServiceBuildsFrozenServiceWithOwnedCursorKey(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{0x51}, 32)
	authority := &finalizedAuthorityStub{page: ReadPage{
		Facts:            []ScopedAccessFact{runtimeDiagnosticFact(now)},
		NextSourceCursor: "authority.next",
		Snapshot:         analyticsSnapshotForRuntime(now),
	}}
	service, err := NewRuntimeService(RuntimeConfig{
		CursorKey: key,
		Now:       func() time.Time { return now },
	}, RuntimeDependencies{Authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	for index := range key {
		key[index] = 0
	}
	query := Query{
		Audience: AudienceTenant, From: now.Add(-time.Hour), To: now.Add(-time.Minute), Limit: 10,
	}
	response, err := service.Read(t.Context(), Actor{
		ScopeKind: "tenant", TenantID: runtimeTenantID(), Permissions: []string{"sites.read"},
	}, query)
	if err != nil {
		t.Fatal(err)
	}
	if response.NextCursor == nil || *response.NextCursor == "" {
		t.Fatal("runtime service did not sign the authority continuation")
	}
	authority.page.NextSourceCursor = ""
	query.Cursor = *response.NextCursor
	if _, err := service.Read(t.Context(), Actor{
		ScopeKind: "tenant", TenantID: runtimeTenantID(), Permissions: []string{"sites.read"},
	}, query); err != nil {
		t.Fatalf("service retained caller cursor-key storage: %v", err)
	}
}

func analyticsSnapshotForRuntime(now time.Time) analyticsrealtime.Snapshot {
	return analyticsrealtime.Snapshot{
		At: now.Add(-time.Second), SourceWatermark: 44,
		FinalizedThrough: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
}

func runtimeTenantID() uuid.UUID {
	return uuid.MustParse("018f0000-0000-7000-8000-000000000001")
}

func runtimeDiagnosticFact(now time.Time) ScopedAccessFact {
	return ScopedAccessFact{TenantID: runtimeTenantID(), Log: analyticslog.AccessLog{
		EventID: "runtime-event", OccurredAt: now.Add(-2 * time.Minute),
		SiteID:    "018f0000-0000-7000-8000-000000000002",
		NodeID:    "018f0000-0000-7000-8000-000000000003",
		RequestID: "runtime-request", TraceID: "runtime-trace",
		ConfigVersion:  "018f0000-0000-7000-8000-000000000004",
		InstallationID: "018f0000-0000-7000-8000-000000000005",
		Host:           "cdn.example.test", StatusCode: 530,
	}}
}
