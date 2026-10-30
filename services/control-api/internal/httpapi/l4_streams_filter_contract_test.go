package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
)

func TestStreamListFilterCanonicalQuery(t *testing.T) {
	for _, query := range []string{
		"protocol=tcp&enabled=true", "protocol=udp&enabled=false",
		"owner_display_id=1", "owner_display_id=9223372036854775807",
		"publication_state=unknown", "publication_state=pending", "publication_state=leased",
		"publication_state=retrying", "publication_state=reconciling", "publication_state=succeeded",
		"publication_state=failed", "publication_state=superseded",
		"cname_domain=edge.example.net", "cname_hostname=tenant-edge",
		"sync_state=done", "sync_state=pending", "sync_state=failed", "admin_status=locked",
		"region_id=6d1c4f0e-3a51-4b8e-9d0c-5f1e2b7a4c90", "node_group_id=6d1c4f0e-3a51-4b8e-9d0c-5f1e2b7a4c90",
	} {
		if _, err := parseStreamListFilter(httptest.NewRequest("GET", "/v1/streams?"+query, nil)); err != nil {
			t.Errorf("valid query %q rejected: %v", query, err)
		}
	}
	for _, query := range []string{
		"protocol=", "protocol=TCP", "protocol=+tcp", "protocol=tcp+", "protocol=http", "protocol=tcp&protocol=tcp",
		"enabled=", "enabled=1", "enabled=0", "enabled=t", "enabled=FALSE", "enabled=+true", "enabled=false+", "enabled=true&enabled=true",
		"owner_display_id=", "owner_display_id=0", "owner_display_id=-1", "owner_display_id=01", "owner_display_id=%2B1",
		"owner_display_id=1.0", "owner_display_id=9223372036854775808", "owner_display_id=1&owner_display_id=2",
		"publication_state=", "publication_state=retry_wait", "publication_state=Pending", "publication_state=+pending",
		"publication_state=normal", "publication_state=pending&publication_state=pending", "sync_state=1", "status=200",
		"sync_state=", "sync_state=Done", "admin_status=", "admin_status=200", "region_id=", "region_id=x", "node_group_id=00000000-0000-0000-0000-000000000000",
		"cname_domain=", "cname_hostname=", "cname_domain=edge&cname_domain=edge",
		"protocol=%ff", "enabled=%zz", "protocol=tcp;enabled=true",
	} {
		if _, err := parseStreamListFilter(httptest.NewRequest("GET", "/v1/streams?"+query, nil)); err == nil {
			t.Errorf("invalid query %q accepted", query)
		}
	}
}

func TestStreamListFilterValuesReachTheService(t *testing.T) {
	filter, err := parseStreamListFilter(httptest.NewRequest("GET", "/v1/streams?owner_display_id=123&protocol=udp&enabled=false&publication_state=retrying&cname_domain=Edge.Example&cname_hostname=Tenant", nil))
	if err != nil || filter.OwnerDisplayID == nil || *filter.OwnerDisplayID != 123 ||
		filter.Protocol != l4forward.ProtocolUDP || filter.Enabled == nil || *filter.Enabled || filter.PublicationState != l4forward.PublicationStateRetrying ||
		filter.CNAMEDomain != "Edge.Example" || filter.CNAMEHostname != "Tenant" {
		t.Fatalf("parsed filter=%+v err=%v", filter, err)
	}
}
