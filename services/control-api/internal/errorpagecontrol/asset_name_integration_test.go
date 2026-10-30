package errorpagecontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// be-gap-2（迁移 509，待出包前全量跑）：上传时给的名称存下、读回、列表带出；
// 不合规名称拒绝；同一幂等键换名称是另一请求（冲突），未命名照旧可用。
func TestErrorPageAssetNamePostgreSQL(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	clock := &testClock{now: time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)}
	limits := staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 8 << 20}}
	service, err := NewServiceWithDependencies(fixture.pool, newMemoryContentStore(), &testScanner{name: "test-scanner"}, limits,
		audit.New(fixture.pool), clock.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	named := initiateRequest(identities.tenantScope, "named", []byte("safe"), "text/plain")
	named.Name = "维护页 404.html"
	created, err := service.InitiateAsset(t.Context(), identities.tenantOwner, named)
	if err != nil || created.Value.Name != "维护页 404.html" {
		t.Fatalf("named initiate = %+v %v", created.Value, err)
	}
	read, err := service.GetAsset(t.Context(), identities.tenantOwner, created.Value.ID)
	if err != nil || read.Name != "维护页 404.html" {
		t.Fatalf("read back = %+v %v", read, err)
	}
	changed := named
	changed.Name = "另一个名字"
	if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key, other name = %v, want conflict", err)
	}
	for _, bad := range []string{" 前空格", "换行\n", string(make([]rune, 129))} {
		request := initiateRequest(identities.tenantScope, "bad-name", []byte("safe"), "text/plain")
		request.Name = bad
		if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("name %q = %v, want invalid input", bad, err)
		}
	}
	unnamed, err := service.InitiateAsset(t.Context(), identities.tenantOwner,
		initiateRequest(identities.tenantScope, "unnamed", []byte("other"), "text/plain"))
	if err != nil || unnamed.Value.Name != "" {
		t.Fatalf("unnamed initiate = %+v %v", unnamed.Value, err)
	}
}
