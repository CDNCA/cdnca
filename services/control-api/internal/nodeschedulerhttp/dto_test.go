package nodeschedulerhttp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

func TestLineGroupMetadataDTORoundTrip(t *testing.T) {
	groupID, tenantID, userID := uuid.New(), uuid.New(), uuid.New()
	body := lineGroupWriteBody{
		Name: "华东线路", Region: "华东", ResolvedValue: "edge-01", Note: "主线路", SortOrder: 8,
		Endpoints: []endpointDTO{},
	}
	request := body.request(groupID, 3, "metadata-update", "metadata-request")
	if request.GroupID != groupID || request.ExpectedRevision != 3 || request.Region != body.Region ||
		request.ResolvedValue != body.ResolvedValue || request.Note != body.Note ||
		request.SortOrder != body.SortOrder || len(request.Endpoints) != 0 {
		t.Fatalf("write request = %#v", request)
	}

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	view := lineGroupView(nodescheduler.LineGroupRevision{
		GroupID: groupID, DisplayID: "7", TenantScopeID: tenantID, Revision: 3, Name: body.Name,
		Region: body.Region, ResolvedValue: body.ResolvedValue, Note: body.Note, SortOrder: body.SortOrder,
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{},
		ConfigurationDigest: make([]byte, 32), CreatedByUserID: userID, CreatedAt: now, SealedAt: now,
	})
	if view.Region != body.Region || view.ResolvedValue != body.ResolvedValue || view.Note != body.Note ||
		view.SortOrder != body.SortOrder || len(view.Endpoints) != 0 {
		t.Fatalf("line group view = %#v", view)
	}
}

func TestEndpointViewCarriesPublished(t *testing.T) {
	published := false
	view := endpointView(nodescheduler.Endpoint{ID: uuid.New(), Published: &published})
	encoded, err := json.Marshal(view)
	if err != nil || !strings.Contains(string(encoded), `"published":false`) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	encoded, _ = json.Marshal(endpointView(nodescheduler.Endpoint{ID: uuid.New()}))
	if strings.Contains(string(encoded), `"published"`) {
		t.Fatalf("unknown published must be omitted: %s", encoded)
	}
}

// fix-backupnotify：线路组列表/详情带出每个地址族当前是否启用备用 IP 及迁移时间；未读取时省略。
func TestLineGroupViewCarriesBackupStates(t *testing.T) {
	changed := time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC)
	view := lineGroupView(nodescheduler.LineGroupRevision{GroupID: uuid.New(), Endpoints: []nodescheduler.Endpoint{},
		BackupStates: []nodescheduler.LineBackupState{{AddressFamily: 4, State: "backup_active",
			BackupAddresses: []string{"192.0.2.20"}, ChangedAt: changed}}})
	encoded, err := json.Marshal(view)
	if err != nil || !strings.Contains(string(encoded),
		`"backup_states":[{"address_family":4,"state":"backup_active","backup_addresses":["192.0.2.20"],"changed_at":"2026-10-27T14:00:00Z"}]`) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	encoded, _ = json.Marshal(lineGroupView(nodescheduler.LineGroupRevision{GroupID: uuid.New()}))
	if strings.Contains(string(encoded), `"backup_states"`) {
		t.Fatalf("unloaded backup states must be omitted: %s", encoded)
	}
}
