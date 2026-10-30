package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

// L4-DEFAULT-01：新建草稿按归属/分组读取生效默认（只读接口的查询参数）。
func TestEffectiveDefaultsQuery(t *testing.T) {
	scope, owner := uuid.New(), uuid.New()
	groupA, groupB := uuid.New(), uuid.New()
	parsed, err := parseEffectiveDefaultsQuery(httptest.NewRequest("GET", "/v1/user-configs/effective?type=stream&target_scope_id="+
		scope.String()+"&owner_id="+owner.String()+"&group_id="+groupA.String()+"&group_id="+groupB.String(), nil))
	if err != nil || parsed.targetScopeID != scope || parsed.ownerID != owner || len(parsed.groupIDs) != 2 ||
		parsed.groupIDs[0] != groupA || parsed.groupIDs[1] != groupB {
		t.Fatalf("parsed = %+v, %v", parsed, err)
	}
	if parsed, err := parseEffectiveDefaultsQuery(httptest.NewRequest("GET", "/v1/user-configs/effective?type=stream", nil)); err != nil ||
		parsed.targetScopeID != uuid.Nil || parsed.ownerID != uuid.Nil || len(parsed.groupIDs) != 0 {
		t.Fatalf("tenant query = %+v, %v", parsed, err)
	}
	for _, query := range []string{
		"", "type=site", "type=stream&type=stream", "type=stream&owner_id=x", "type=stream&target_scope_id=x",
		"type=stream&group_id=x", "type=stream&owner_id=" + owner.String() + "&owner_id=" + owner.String(), "type=stream&page=1",
	} {
		if _, err := parseEffectiveDefaultsQuery(httptest.NewRequest("GET", "/v1/user-configs/effective?"+query, nil)); err == nil {
			t.Errorf("invalid query %q accepted", query)
		}
	}
}

// 未配置的项必须是 null（前端据此保留自身兜底值），不能是 tcp/rr/false 这类看似真实的默认。
func TestEffectiveDefaultsJSONKeepsUnsetAsNull(t *testing.T) {
	balance := l4forward.BalanceWayIPHash
	raw, err := json.Marshal(l4forward.FieldDefaults{BalanceWay: &balance})
	if err != nil || string(raw) != `{"protocol":null,"proxy_protocol_inbound":null,"balance_way":"ip_hash"}` {
		t.Fatalf("json = %s, %v", raw, err)
	}
}
