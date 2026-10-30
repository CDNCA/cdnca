package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestL4ForwardingHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	platform, err := identity.NewStore(pool).BootstrapPlatformUser(
		context.Background(), "stream-admin", "Stream Admin", passwordHash, "bootstrap-stream-admin",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenant := insertL4Tenant(t, pool, "Stream Tenant", "stream-owner", passwordHash, []string{"streams.read", "streams.manage"})
	other := insertL4Tenant(t, pool, "Other Tenant", "other-stream-owner", passwordHash, []string{"streams.read", "streams.manage"})
	viewerID := insertL4ScopeUser(t, pool, tenant.scopeID, "stream-viewer", "Stream Viewer", passwordHash, []string{"streams.read"})
	deniedID := insertL4ScopeUser(t, pool, tenant.scopeID, "stream-denied", "Stream Denied", passwordHash, nil)
	if platform.UserID == uuid.Nil || viewerID == uuid.Nil || deniedID == uuid.Nil {
		t.Fatal("L4 principals were not created")
	}

	tokens, err := identity.NewTokenManager("l4-integration-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	adminAuth, _ := loginOK(t, client, server.URL, "stream-admin")
	ownerAuth, _ := loginOK(t, client, server.URL, "stream-owner")
	otherAuth, _ := loginOK(t, client, server.URL, "other-stream-owner")
	viewerAuth, _ := loginOK(t, client, server.URL, "stream-viewer")
	deniedAuth, _ := loginOK(t, client, server.URL, "stream-denied")
	installL4AutomaticPolicy(t, pool, tenant)
	installL4AutomaticPolicy(t, pool, other)
	group := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "flow-group", streamGroupRequest{Name: "转发组"})

	tcp := validStreamFields(tenant, "TCP gateway", l4forward.ProtocolTCP, 18100, "192.0.2.10")
	createTCP := createStreamRequest{Fields: tcp, GroupIDs: []string{group.ID.String()}}
	created := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "create-tcp", createTCP)
	if created.Owner != nil || created.PackageName != nil || created.PackageExpiresAt != nil || created.DisplayID != "1" || created.ScopeID != tenant.scopeID || created.Revision != 1 ||
		created.PublishIntent.Version != 1 || created.PublishIntent.State != l4forward.PublicationStateUnknown ||
		created.PublishIntent.RuntimeSpec.Listener.Protocol != l4forward.ProtocolTCP ||
		created.PublishIntent.RuntimeSpec.Listener.Port != 18100 || created.PublishIntent.RuntimeSpec.Endpoint.Address != "192.0.2.10" ||
		len(created.Groups) != 1 || created.Groups[0].ID != group.ID {
		t.Fatalf("created TCP rule = %#v", created)
	}
	var automaticOperation string
	var automaticResourceID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT operation, source_resource_id
		FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_resource_id=$2`, tenant.scopeID, created.ID).
		Scan(&automaticOperation, &automaticResourceID); err != nil {
		t.Fatalf("load automatic L4 publication request: %v", err)
	}
	if automaticOperation != "stream.create" || automaticResourceID != created.ID {
		t.Fatalf("automatic L4 publication request = %q/%s", automaticOperation, automaticResourceID)
	}
	// 506 起四层转发不挂网站，按套餐的 CNAME 读套餐的共享分配（cn_package）：快照改为 shared，种一条 LKG 分配。
	seedL4PackageCNAME(t, pool, tenant, "l4.edge.example")

	replayed := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "create-tcp", createTCP)
	if replayed.ID != created.ID || replayed.DisplayID != created.DisplayID || replayed.PublishIntent.ID != created.PublishIntent.ID || replayed.PackageExpiresAt != nil {
		t.Fatalf("idempotent create returned different result: %#v %#v", created, replayed)
	}
	changed := tcp
	changed.Name = "changed replay"
	response := l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: changed}, ownerAuth.AccessToken, "create-tcp", "")
	assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
	response.Body.Close()

	foreignPackage := tcp
	foreignPackage.Name = "foreign package"
	foreignPackage.ListenPort = 18160
	foreignPackage.PackageSubscriptionID = new(other.subscriptionID)
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: foreignPackage}, ownerAuth.AccessToken, "foreign-package", "")
	// 自 b2d72c9d 起配额检查走 packageaddon.LockRuntimeLimits：别的租户的套餐在本租户下查不到，
	// 与已到期套餐一样回 409 package_subscription_inactive，不区分“不存在”和“未生效”。
	assertError(t, response, http.StatusConflict, "package_subscription_inactive", "")
	response.Body.Close()

	udpProxy := validStreamFields(tenant, "invalid UDP proxy", l4forward.ProtocolUDP, 18101, "2001:db8::10")
	udpProxy.ProxyProtocolV1 = true
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: udpProxy}, ownerAuth.AccessToken, "udp-proxy", "")
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()

	udp := validStreamFields(tenant, "UDP gateway", l4forward.ProtocolUDP, 18100, "2001:db8::10")
	createdUDP := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "create-udp", createStreamRequest{Fields: udp})
	if createdUDP.DisplayID != "2" || createdUDP.Protocol != l4forward.ProtocolUDP || createdUDP.UpstreamAddress != "2001:db8::10" {
		t.Fatalf("created UDP rule = %#v", createdUDP)
	}
	conflictingTCP := validStreamFields(tenant, "TCP conflict", l4forward.ProtocolTCP, 18100, "192.0.2.11")
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: conflictingTCP}, ownerAuth.AccessToken, "tcp-conflict", "")
	assertError(t, response, http.StatusConflict, "stream_port_conflict", "")
	response.Body.Close()
	conflictingName := validStreamFields(tenant, tcp.Name, l4forward.ProtocolTCP, 18150, "192.0.2.12")
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: conflictingName}, ownerAuth.AccessToken, "name-conflict", "")
	assertError(t, response, http.StatusConflict, "stream_name_conflict", "")
	response.Body.Close()

	otherTCP := validStreamFields(other, "Other TCP", l4forward.ProtocolTCP, 18200, "198.51.100.20")
	otherCreated := createL4Forward(t, client, server.URL, adminAuth.AccessToken, "admin-other", createStreamRequest{
		TargetScopeID: other.scopeID.String(), OwnerID: other.userID.String(), Fields: otherTCP,
	})
	if otherCreated.DisplayID != "1" || otherCreated.Owner == nil || otherCreated.Owner.ID != other.userID {
		t.Fatalf("platform response did not include owner: %#v", otherCreated.Owner)
	}
	// 自 b2d72c9d 起转发归属人必须是套餐持有人（l4forward/package_limits.go 的 OwnerUserID 校验），
	// 所以替 viewer 建的转发要挂 viewer 自己的套餐。
	viewerFields := validStreamFields(tenant, "Viewer owned TCP", l4forward.ProtocolTCP, 18250, "198.51.100.25")
	viewerFields.PackageSubscriptionID = new(insertL4PackageSubscription(t, pool, tenant.scopeID, viewerID))
	viewerOwned := createL4Forward(t, client, server.URL, adminAuth.AccessToken, "admin-viewer-owned", createStreamRequest{
		TargetScopeID: tenant.scopeID.String(), OwnerID: viewerID.String(), Fields: viewerFields,
	})
	ownerList := listL4Forwards(t, client, server.URL+"/v1/streams?page=1&limit=20", ownerAuth.AccessToken)
	if ownerList.Total != 2 {
		t.Fatalf("owner list total = %d, want 2", ownerList.Total)
	}
	var listedCNAME *string
	for _, item := range ownerList.Items {
		if item.ID == created.ID {
			listedCNAME = item.CNAME
			break
		}
	}
	if listedCNAME == nil || *listedCNAME != "l4.edge.example" {
		t.Fatalf("list CNAME = %v, want l4.edge.example", listedCNAME)
	}
	var packageEndsAt, otherPackageEndsAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT ends_at FROM package_subscriptions WHERE tenant_scope_id=$1 AND id=$2`,
		tenant.scopeID, tenant.subscriptionID).Scan(&packageEndsAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT ends_at FROM package_subscriptions WHERE tenant_scope_id=$1 AND id=$2`,
		other.scopeID, other.subscriptionID).Scan(&otherPackageEndsAt); err != nil {
		t.Fatal(err)
	}
	for _, item := range ownerList.Items {
		if item.PackageName == nil || *item.PackageName != "L4 HTTP "+tenant.subscriptionID.String() {
			t.Fatalf("persisted package name = %v", item.PackageName)
		}
		if item.PackageExpiresAt == nil || !item.PackageExpiresAt.Equal(packageEndsAt) {
			t.Fatalf("persisted package expiry = %v, want %v", item.PackageExpiresAt, packageEndsAt)
		}
	}
	readBack := getL4Forward(t, client, server.URL, created.ID, ownerAuth.AccessToken)
	if readBack.CNAME == nil || *readBack.CNAME != "l4.edge.example" {
		t.Fatalf("detail CNAME = %v, want l4.edge.example", readBack.CNAME)
	}
	if readBack.PackageName == nil || *readBack.PackageName != "L4 HTTP "+tenant.subscriptionID.String() {
		t.Fatalf("detail package name = %v", readBack.PackageName)
	}
	if readBack.PackageExpiresAt == nil || !readBack.PackageExpiresAt.Equal(packageEndsAt) {
		t.Fatalf("detail package expiry = %v, want %v", readBack.PackageExpiresAt, packageEndsAt)
	}
	response = l4Request(t, client, http.MethodGet, server.URL+"/v1/streams/"+created.ID.String(), nil, otherAuth.AccessToken, "", "")
	assertError(t, response, http.StatusNotFound, "stream_not_found", "")
	response.Body.Close()
	var expiryWrite map[string]any
	encodedWrite, err := json.Marshal(createTCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encodedWrite, &expiryWrite); err != nil {
		t.Fatal(err)
	}
	expiryWrite["package_expires_at"] = "2099-01-01T00:00:00Z"
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", expiryWrite, ownerAuth.AccessToken, "write-package-expiry", "")
	assertError(t, response, http.StatusBadRequest, "invalid_request", "")
	response.Body.Close()
	otherList := listL4Forwards(t, client, server.URL+"/v1/streams?page=1&limit=20", otherAuth.AccessToken)
	if otherList.Total != 1 || otherList.Items[0].ID != otherCreated.ID ||
		otherList.Items[0].PackageExpiresAt == nil || !otherList.Items[0].PackageExpiresAt.Equal(otherPackageEndsAt) ||
		otherList.Items[0].PackageName == nil || *otherList.Items[0].PackageName != "L4 HTTP "+other.subscriptionID.String() {
		t.Fatalf("other tenant list = %#v", otherList)
	}
	adminList := listL4Forwards(t, client, server.URL+"/v1/streams?page=1&limit=20&protocol=tcp&enabled=true", adminAuth.AccessToken)
	if adminList.Total != 3 || adminList.Items[0].Owner == nil {
		t.Fatalf("admin filtered list = %#v", adminList)
	}

	response = l4Request(t, client, http.MethodGet, server.URL+"/v1/streams", nil, deniedAuth.AccessToken, "", "")
	assertError(t, response, http.StatusForbidden, "permission_denied", "")
	response.Body.Close()
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: validStreamFields(tenant, "Viewer denied", "tcp", 18300, "192.0.2.30")}, viewerAuth.AccessToken, "viewer-denied", "")
	assertError(t, response, http.StatusForbidden, "permission_denied", "")
	response.Body.Close()
	viewerList := listL4Forwards(t, client, server.URL+"/v1/streams?page=1&limit=20", viewerAuth.AccessToken)
	if viewerList.Total != 1 || viewerList.Items[0].ID != viewerOwned.ID {
		t.Fatalf("viewer ownership filter = %#v", viewerList)
	}
	oneRuneName := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "one-rune-name", createStreamRequest{
		Fields: validStreamFields(tenant, "  中  ", l4forward.ProtocolTCP, 18310, "192.0.2.31"),
	})
	if oneRuneName.Name != "中" {
		t.Fatalf("stored one-rune name = %q, want %q", oneRuneName.Name, "中")
	}
	boundaryName := strings.Repeat("界", 128)
	boundary := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "128-rune-name", createStreamRequest{
		Fields: validStreamFields(tenant, boundaryName, l4forward.ProtocolTCP, 18311, "192.0.2.32"),
	})
	if boundary.Name != boundaryName {
		t.Fatalf("stored 128-rune name has %d runes, want 128", len([]rune(boundary.Name)))
	}

	updatedFields := tcp
	updatedFields.Enabled = false
	updatedFields.UpstreamAddress = "2001:db8::20"
	for _, token := range []string{otherAuth.AccessToken, viewerAuth.AccessToken} {
		response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+created.ID.String(), updateStreamRequest{
			ExpectedRevision: created.Revision, Fields: updatedFields,
		}, token, "foreign-update", `"1"`)
		wantStatus, wantCode := http.StatusNotFound, "stream_not_found"
		if token == viewerAuth.AccessToken {
			wantStatus, wantCode = http.StatusForbidden, "permission_denied"
		}
		assertError(t, response, wantStatus, wantCode, "")
		response.Body.Close()
	}
	updated := updateL4Forward(t, client, server.URL, created.ID, ownerAuth.AccessToken, "disable-tcp", updateStreamRequest{
		ExpectedRevision: created.Revision, Fields: updatedFields,
	}, created.Revision)
	if updated.DisplayID != created.DisplayID || updated.Revision != 2 || updated.Enabled || updated.PublishIntent.DesiredState != "disabled" ||
		updated.PublishIntent.RuntimeSpec.Endpoint.Address != "2001:db8::20" ||
		len(updated.Groups) != 1 || updated.Groups[0].ID != group.ID {
		t.Fatalf("updated rule = %#v", updated)
	}
	replayedUpdate := updateL4Forward(t, client, server.URL, created.ID, ownerAuth.AccessToken, "disable-tcp", updateStreamRequest{
		ExpectedRevision: created.Revision, Fields: updatedFields,
	}, created.Revision)
	if replayedUpdate.Revision != updated.Revision || replayedUpdate.PublishIntent.ID != updated.PublishIntent.ID ||
		len(replayedUpdate.Groups) != 1 || replayedUpdate.Groups[0].ID != group.ID {
		t.Fatalf("replayed grouped update = %#v", replayedUpdate)
	}

	concurrent := make([]*http.Response, 2)
	var wait sync.WaitGroup
	for index := range concurrent {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			fields := updatedFields
			fields.Name = []string{"TCP concurrent A", "TCP concurrent B"}[index]
			concurrent[index], _ = performL4Request(client, http.MethodPatch, server.URL+"/v1/streams/"+created.ID.String(), updateStreamRequest{
				ExpectedRevision: updated.Revision, Fields: fields,
			}, ownerAuth.AccessToken, []string{"update-a", "update-b"}[index], `"`+strconv.FormatInt(updated.Revision, 10)+`"`)
		}()
	}
	wait.Wait()
	statuses := map[int]int{}
	for _, item := range concurrent {
		statuses[item.StatusCode]++
		item.Body.Close()
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatalf("concurrent update statuses = %#v", statuses)
	}
	current := getL4Forward(t, client, server.URL, created.ID, ownerAuth.AccessToken)

	deletes := make([]*http.Response, 2)
	wait = sync.WaitGroup{}
	for index := range deletes {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			deletes[index], _ = performL4Request(client, http.MethodDelete, server.URL+"/v1/streams/"+created.ID.String(), nil,
				ownerAuth.AccessToken, []string{"delete-a", "delete-b"}[index], `"`+strconv.FormatInt(current.Revision, 10)+`"`)
		}()
	}
	wait.Wait()
	statuses = map[int]int{}
	for _, item := range deletes {
		statuses[item.StatusCode]++
		item.Body.Close()
	}
	if statuses[http.StatusNoContent] != 1 || statuses[http.StatusNotFound] != 1 {
		t.Fatalf("concurrent delete statuses = %#v", statuses)
	}
	replacement := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "replacement", createStreamRequest{
		Fields: validStreamFields(tenant, "Replacement TCP", l4forward.ProtocolTCP, 18100, "192.0.2.50"),
	})
	if replacement.ListenPort != 18100 {
		t.Fatalf("replacement did not reuse deleted port: %#v", replacement)
	}
	// The tenant fixture already owns a real site listening on 18080.
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{
		Fields: validStreamFields(tenant, "Site port conflict", l4forward.ProtocolTCP, 18080, "192.0.2.60"),
	}, ownerAuth.AccessToken, "site-port-conflict", "")
	assertError(t, response, http.StatusConflict, "stream_port_conflict", "")
	response.Body.Close()

	var auditCount, intentCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action LIKE 'stream.%'`).Scan(&auditCount); err != nil {
		t.Fatalf("count L4 audit events: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM l4_publish_intents`).Scan(&intentCount); err != nil {
		t.Fatalf("count L4 publish intents: %v", err)
	}
	if auditCount < 7 || intentCount != auditCount {
		t.Fatalf("audit/intent count = %d/%d", auditCount, intentCount)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE l4_publish_intents SET desired_state = 'disabled'`); err == nil {
		t.Fatal("immutable publish intent update unexpectedly succeeded")
	}
}

func TestL4OpenAPIUsesExactPublicationProjection(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "api", "control-l4-forward.openapi.yaml"))
	if err != nil {
		t.Fatalf("read control OpenAPI: %v", err)
	}
	source := string(contents)
	for _, required := range []string{
		"configuration_source_revision: {type: integer, format: int64, minimum: 1}",
		"state: {type: string, enum: [unknown, pending, leased, retrying, reconciling, succeeded, failed, superseded]}",
		"automatic_request_id:", "publication_id:", "rollout_id:",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("L4 OpenAPI publication projection missing %q", required)
		}
	}
	for _, operation := range []struct {
		start string
		end   string
	}{
		{start: "    post:\n      operationId: createStream", end: "  /v1/streams/{id}:"},
		{start: "    patch:\n      operationId: updateStream", end: "    delete:\n      operationId: deleteStream"},
	} {
		start := strings.Index(source, operation.start)
		if start < 0 {
			t.Fatalf("missing L4 OpenAPI operation %q", operation.start)
		}
		end := strings.Index(source[start:], operation.end)
		if end < 0 {
			t.Fatalf("missing L4 OpenAPI operation boundary %q", operation.end)
		}
		section := source[start : start+end]
		if !strings.Contains(section, "'415':") || !strings.Contains(section, "UnsupportedMediaType") {
			t.Fatalf("L4 OpenAPI operation %q does not declare the 415 unsupported_media_type contract", operation.start)
		}
	}
}

func TestL4StreamRawBodyContract(t *testing.T) {
	tests := []struct {
		name         string
		body         func(bool) []byte
		contentTypes []string
		wantStatus   int
		wantCode     string
		wantName     string
		wantCalls    int
	}{
		{
			name: "literal invalid UTF-8", body: func(update bool) []byte {
				return rawL4StreamBody([]byte{'b', 'a', 'd', 0xff, 'n', 'a', 'm', 'e'}, update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "unpaired high surrogate value", body: func(update bool) []byte {
				return rawL4StreamBody([]byte(`\ud800`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "unpaired low surrogate value", body: func(update bool) []byte {
				return rawL4StreamBody([]byte(`\udc00`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "malformed surrogate pair value", body: func(update bool) []byte {
				return rawL4StreamBody([]byte(`\ud800\u0041`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "unpaired surrogate key", body: func(update bool) []byte {
				return prependL4StreamMember([]byte(`"\ud800":true`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "valid multibyte Chinese", body: func(update bool) []byte {
				return rawL4StreamBody([]byte("中文入口"), update)
			}, contentTypes: []string{"application/json; charset=utf-8"}, wantName: "中文入口", wantCalls: 1,
		},
		{
			name: "valid paired surrogate", body: func(update bool) []byte {
				return rawL4StreamBody([]byte(`\ud83d\ude00入口`), update)
			}, contentTypes: []string{"application/json"}, wantName: "😀入口", wantCalls: 1,
		},
		{
			name: "duplicate top-level name", body: func(update bool) []byte {
				return rawL4StreamDuplicateNameBody([]byte("first"), []byte("中文入口"), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "duplicate nested object key", body: func(update bool) []byte {
				return prependL4StreamMember([]byte(`"metadata":{"outer":{"key":1,"key":2}}`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "duplicate object key inside array", body: func(update bool) []byte {
				return prependL4StreamMember([]byte(`"metadata":[{"key":1,"key":2}]`), update)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "unknown field", body: func(update bool) []byte {
				body := rawL4StreamBody([]byte("中文入口"), update)
				return append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "trailing value", body: func(update bool) []byte {
				return append(rawL4StreamBody([]byte("中文入口"), update), []byte(` {}`)...)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "null body", body: func(bool) []byte { return []byte("null") },
			contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "validation_error",
		},
		{
			name: "body exactly one MiB", body: func(update bool) []byte {
				return paddedL4StreamBody(update, 1<<20)
			}, contentTypes: []string{"application/json"}, wantName: "boundary", wantCalls: 1,
		},
		{
			name: "body one byte over one MiB", body: func(update bool) []byte {
				return paddedL4StreamBody(update, (1<<20)+1)
			}, contentTypes: []string{"application/json"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request",
		},
		{
			name: "missing content type", body: func(update bool) []byte {
				return rawL4StreamBody([]byte("中文入口"), update)
			}, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
		},
		{
			name: "duplicate content type", body: func(update bool) []byte {
				return rawL4StreamBody([]byte("中文入口"), update)
			}, contentTypes: []string{"application/json", "application/json"}, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
		},
		{
			name: "malformed content type", body: func(update bool) []byte {
				return rawL4StreamBody([]byte("中文入口"), update)
			}, contentTypes: []string{"application/json; charset"}, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
		},
		{
			name: "unsupported content type", body: func(update bool) []byte {
				return rawL4StreamBody([]byte("中文入口"), update)
			}, contentTypes: []string{"text/plain"}, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type",
		},
	}
	for _, update := range []bool{false, true} {
		operation := "create"
		if update {
			operation = "update"
		}
		for _, test := range tests {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				service := new(recordingL4StreamWriteService)
				handler := l4StreamWriteHandler{
					server:  new(Server),
					service: service,
					authorize: func(http.ResponseWriter, *http.Request, string) (identity.Principal, bool) {
						return identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}, true
					},
				}
				method, path := http.MethodPost, "/v1/streams"
				if update {
					method, path = http.MethodPatch, "/v1/streams/"+uuid.NewString()
				}
				request := httptest.NewRequest(method, path, bytes.NewReader(test.body(update)))
				request.Header.Set("Idempotency-Key", "raw-body-contract")
				if update {
					request.Header.Set("If-Match", `"1"`)
				}
				for _, contentType := range test.contentTypes {
					request.Header.Add("Content-Type", contentType)
				}
				if update {
					request.SetPathValue("id", strings.TrimPrefix(path, "/v1/streams/"))
				}
				response := httptest.NewRecorder()
				if update {
					handler.handleUpdate(response, request)
				} else {
					handler.handleCreate(response, request)
				}
				wantStatus := test.wantStatus
				if wantStatus == 0 && update {
					wantStatus = http.StatusOK
				} else if wantStatus == 0 {
					wantStatus = http.StatusCreated
				}
				if response.Code != wantStatus {
					t.Fatalf("status=%d recorded name=%q want status=%d", response.Code, service.name(), wantStatus)
				}
				if service.calls() != test.wantCalls {
					t.Fatalf("service calls=%d want %d", service.calls(), test.wantCalls)
				}
				if test.wantName != "" && service.name() != test.wantName {
					t.Fatalf("recorded name=%q want %q", service.name(), test.wantName)
				}
				if test.wantCode != "" {
					var envelope errorEnvelope
					if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
						t.Fatalf("decode error response: %v", err)
					}
					if envelope.Error.Code != test.wantCode {
						t.Fatalf("error code=%q want %q", envelope.Error.Code, test.wantCode)
					}
					if bytes.Contains(response.Body.Bytes(), []byte{0xff}) ||
						bytes.Contains(response.Body.Bytes(), []byte("�")) ||
						bytes.Contains(response.Body.Bytes(), []byte(`\ufffd`)) {
						t.Fatalf("error response leaked rejected bytes: %q", response.Body.Bytes())
					}
				}
			})
		}
	}
}

func TestL4StreamUpdateRequiresStrongIfMatch(t *testing.T) {
	tests := []struct {
		name          string
		ifMatchValues []string
		wantStatus    int
		wantCalls     int
	}{
		{name: "missing", wantStatus: http.StatusBadRequest},
		{name: "weak", ifMatchValues: []string{`W/"1"`}, wantStatus: http.StatusBadRequest},
		{name: "list", ifMatchValues: []string{`"1", "2"`}, wantStatus: http.StatusBadRequest},
		{name: "duplicate fields", ifMatchValues: []string{`"1"`, `"1"`}, wantStatus: http.StatusBadRequest},
		{name: "body and header mismatch", ifMatchValues: []string{`"2"`}, wantStatus: http.StatusBadRequest},
		{name: "matching strong revision", ifMatchValues: []string{`"1"`}, wantStatus: http.StatusOK, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := new(recordingL4StreamWriteService)
			handler := l4StreamWriteHandler{
				server: new(Server), service: service,
				authorize: func(http.ResponseWriter, *http.Request, string) (identity.Principal, bool) {
					return identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}, true
				},
			}
			id := uuid.NewString()
			request := httptest.NewRequest(http.MethodPatch, "/v1/streams/"+id, bytes.NewReader(rawL4StreamBody([]byte("strong revision"), true)))
			request.SetPathValue("id", id)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "strong-revision")
			for _, value := range test.ifMatchValues {
				request.Header.Add("If-Match", value)
			}
			response := httptest.NewRecorder()
			handler.handleUpdate(response, request)
			if response.Code != test.wantStatus || service.calls() != test.wantCalls {
				t.Fatalf("status/calls = %d/%d, want %d/%d", response.Code, service.calls(), test.wantStatus, test.wantCalls)
			}
			if test.wantCalls == 1 && service.updates[0].ExpectedRevision != 1 {
				t.Fatalf("service revision = %d, want 1", service.updates[0].ExpectedRevision)
			}
			if test.wantStatus == http.StatusBadRequest {
				var envelope errorEnvelope
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatalf("decode error: %v", err)
				}
				if envelope.Error.Code != "validation_error" {
					t.Fatalf("error code = %q, want validation_error", envelope.Error.Code)
				}
			}
		})
	}
}

func TestL4WriteTransactionRollback(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	tenant := insertL4Tenant(t, pool, "Rollback Tenant", "stream-rollback", passwordHash, []string{"streams.read", "streams.manage"})
	installL4AutomaticPolicy(t, pool, tenant)
	tokens, err := identity.NewTokenManager("l4-rollback-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth, _ := loginOK(t, client, server.URL, "stream-rollback")
	installL4RollbackFailureTriggers(t, pool)

	tests := []struct {
		name      string
		key       string
		requestID string
		port      uint16
		host      string
	}{
		{name: "publish intent", key: "rollback-intent", requestID: "rollback-intent", port: 19101, host: "192.0.2.201"},
		{name: "automatic enqueue", key: "rollback-enqueue", requestID: "rollback-enqueue", port: 19102, host: "192.0.2.202"},
		{name: "audit append", key: "rollback-audit", requestID: "rollback-audit", port: 19103, host: "192.0.2.203"},
		{name: "idempotency completion", key: "rollback-complete", requestID: "rollback-complete", port: 19104, host: "192.0.2.204"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var intentsBefore, publishVersionBefore, sourceRevisionBefore int64
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM l4_publish_intents`).Scan(&intentsBefore); err != nil {
				t.Fatalf("count intents before: %v", err)
			}
			if err := pool.QueryRow(context.Background(), `
				SELECT COALESCE((SELECT current_version FROM l4_scope_publish_counters WHERE scope_id=$1),0)`, tenant.scopeID).
				Scan(&publishVersionBefore); err != nil {
				t.Fatalf("load publish version before: %v", err)
			}
			if err := pool.QueryRow(context.Background(), `SELECT COALESCE(
				(SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1),0)`, tenant.scopeID).Scan(&sourceRevisionBefore); err != nil {
				t.Fatalf("load source revision before: %v", err)
			}
			response, err := performL4Request(client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{
				Fields: validStreamFields(tenant, "Rollback "+test.name, l4forward.ProtocolTCP, test.port, test.host),
			}, auth.AccessToken, test.key, "", test.requestID)
			if err != nil {
				t.Fatalf("perform rollback request: %v", err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read rollback response: %v", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d body=%s", response.StatusCode, body)
			}
			var envelope errorEnvelope
			if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error.Code != "internal_error" {
				t.Fatalf("error = %#v decode=%v", envelope, err)
			}
			if bytes.Contains(body, []byte("injected L4")) {
				t.Fatalf("internal persistence message leaked: %s", body)
			}
			assertL4WriteRolledBack(t, pool, tenant.scopeID, "Rollback "+test.name, test.key, test.requestID,
				intentsBefore, publishVersionBefore, sourceRevisionBefore)
		})
	}
}

type recordingL4StreamWriteService struct {
	creates []l4forward.CreateRequest
	updates []l4forward.UpdateRequest
}

func (s *recordingL4StreamWriteService) Create(_ context.Context, _ l4forward.Actor, request l4forward.CreateRequest) (l4forward.WriteResult, error) {
	if request.Fields.Name == "" {
		return l4forward.WriteResult{}, l4forward.ErrInvalidInput
	}
	s.creates = append(s.creates, request)
	return recordedL4WriteResult(1), nil
}

func (s *recordingL4StreamWriteService) Update(_ context.Context, _ l4forward.Actor, request l4forward.UpdateRequest) (l4forward.WriteResult, error) {
	if request.Fields.Name == "" {
		return l4forward.WriteResult{}, l4forward.ErrInvalidInput
	}
	s.updates = append(s.updates, request)
	return recordedL4WriteResult(2), nil
}

func (s *recordingL4StreamWriteService) calls() int {
	return len(s.creates) + len(s.updates)
}

func (s *recordingL4StreamWriteService) name() string {
	if len(s.creates) == 1 {
		return s.creates[0].Fields.Name
	}
	if len(s.updates) == 1 {
		return s.updates[0].Fields.Name
	}
	return ""
}

func recordedL4WriteResult(revision int64) l4forward.WriteResult {
	return l4forward.WriteResult{Forward: l4forward.Forward{
		Revision: revision,
		PublishIntent: l4forward.PublishIntent{
			Version: revision,
		},
	}}
}

func rawL4StreamBody(name []byte, update bool) []byte {
	prefix := []byte(`{"name":"`)
	if update {
		prefix = []byte(`{"expected_revision":1,"name":"`)
	}
	body := append(prefix, name...)
	return append(body, []byte(`","protocol":"tcp","listen_address":"*","listen_port":18100,"upstream_address":"192.0.2.10","upstream_port":9000,"connect_timeout_ms":3000,"response_timeout_ms":30000,"proxy_protocol_v1":false,"enabled":true}`)...)
}

func rawL4StreamDuplicateNameBody(first, last []byte, update bool) []byte {
	prefix := []byte(`{"name":"`)
	if update {
		prefix = []byte(`{"expected_revision":1,"name":"`)
	}
	body := append(prefix, first...)
	body = append(body, []byte(`","name":"`)...)
	body = append(body, last...)
	return append(body, []byte(`","protocol":"tcp","listen_address":"*","listen_port":18100,"upstream_address":"192.0.2.10","upstream_port":9000,"connect_timeout_ms":3000,"response_timeout_ms":30000,"proxy_protocol_v1":false,"enabled":true}`)...)
}

func prependL4StreamMember(member []byte, update bool) []byte {
	body := rawL4StreamBody([]byte("boundary"), update)
	return append(append(append([]byte{'{'}, member...), ','), body[1:]...)
}

func paddedL4StreamBody(update bool, size int) []byte {
	body := rawL4StreamBody([]byte("boundary"), update)
	if len(body) > size {
		panic("L4 body exceeds requested padded size")
	}
	return append(body, bytes.Repeat([]byte{' '}, size-len(body))...)
}

func TestL4MigrationRollbackAndReapply(t *testing.T) {
	pool := migrationRoundTripPool(t, 7)
	ctx := context.Background()
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 007) error = %v", err)
	}
	for _, table := range []string{"l4_forwards", "l4_publish_intents", "l4_write_requests"} {
		var relation *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1)::text", table).Scan(&relation); err != nil {
			t.Fatalf("inspect %s after rollback: %v", table, err)
		}
		if relation != nil {
			t.Fatalf("%s still exists after migration rollback", table)
		}
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("Migrate(up 007) error = %v", err)
	}
	var permissionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE name IN ('streams.read', 'streams.manage')`).Scan(&permissionCount); err != nil {
		t.Fatalf("inspect stream permissions after reapply: %v", err)
	}
	if permissionCount != 2 {
		t.Fatalf("stream permission count = %d, want 2", permissionCount)
	}
}

func rollbackToMigration(t *testing.T, pool *pgxpool.Pool, targetVersion int64) {
	t.Helper()
	ctx := context.Background()
	for {
		var latestVersion int64
		if err := pool.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&latestVersion); err != nil {
			t.Fatalf("inspect latest migration: %v", err)
		}
		if latestVersion < targetVersion {
			t.Fatalf("target migration %d is not applied; latest is %d", targetVersion, latestVersion)
		}
		if latestVersion == targetVersion {
			return
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down %d) error = %v", latestVersion, err)
		}
	}
}

type l4TenantFixture struct {
	scopeID        uuid.UUID
	userID         uuid.UUID
	subscriptionID uuid.UUID
	// 转发必须挂在站点上（runtime spec v2 的 site_id 即来自这里），站点由租户夹具一并建好。
	siteID uuid.UUID
}

func installL4AutomaticPolicy(t *testing.T, pool *pgxpool.Pool, tenant l4TenantFixture) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO edge_automatic_publication_policy_facts (
			target_scope_id, revision, mode, node_ids, activation_timeout_ms, observation_window_ms,
			required_consecutive_successes, max_attempts, deadline_window_seconds,
			actor_scope_id, actor_user_id, reason, created_at
		) VALUES ($1,1,'automatic',ARRAY[$2]::uuid[],1000,1000,1,3,300,$1,$3,'l4_integration_test',now())`,
		tenant.scopeID, uuid.New(), tenant.userID); err != nil {
		t.Fatalf("install automatic L4 policy: %v", err)
	}
}

func installL4RollbackFailureTriggers(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	statements := []string{
		`CREATE FUNCTION l4_test_fail_intent() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.runtime_spec #>> '{endpoint,address}' = '192.0.2.201' THEN
				RAISE EXCEPTION 'injected L4 publish intent failure';
			END IF;
			RETURN NEW;
		END $$`,
		`CREATE TRIGGER l4_test_fail_intent BEFORE INSERT ON l4_publish_intents
		FOR EACH ROW EXECUTE FUNCTION l4_test_fail_intent()`,
		`CREATE FUNCTION l4_test_fail_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.source_request_id = 'rollback-enqueue' THEN
				RAISE EXCEPTION 'injected L4 automatic enqueue failure';
			END IF;
			RETURN NEW;
		END $$`,
		`CREATE TRIGGER l4_test_fail_enqueue BEFORE INSERT ON edge_automatic_publication_requests
		FOR EACH ROW EXECUTE FUNCTION l4_test_fail_enqueue()`,
		`CREATE FUNCTION l4_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'stream.create' AND NEW.request_id = 'rollback-audit' THEN
				RAISE EXCEPTION 'injected L4 audit failure';
			END IF;
			RETURN NEW;
		END $$`,
		`CREATE TRIGGER l4_test_fail_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION l4_test_fail_audit()`,
		`CREATE FUNCTION l4_test_fail_complete() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.idempotency_key = 'rollback-complete' AND NEW.completed_at IS NOT NULL THEN
				RAISE EXCEPTION 'injected L4 idempotency completion failure';
			END IF;
			RETURN NEW;
		END $$`,
		`CREATE TRIGGER l4_test_fail_complete BEFORE UPDATE ON l4_write_requests
		FOR EACH ROW EXECUTE FUNCTION l4_test_fail_complete()`,
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement); err != nil {
			t.Fatalf("install L4 rollback failure trigger: %v", err)
		}
	}
}

func assertL4WriteRolledBack(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	name, key, requestID string,
	wantIntents, wantPublishVersion, wantSourceRevision int64,
) {
	t.Helper()
	var forwards, writes, audits, automaticRequests, intents, publishVersion, sourceRevision int64
	if err := pool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM l4_forwards WHERE scope_id=$1 AND name=$2),
			(SELECT count(*) FROM l4_write_requests WHERE target_scope_id=$1 AND idempotency_key=$3),
			(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='stream.create' AND request_id=$4),
			(SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1 AND source_request_id=$4),
			(SELECT count(*) FROM l4_publish_intents),
			COALESCE((SELECT current_version FROM l4_scope_publish_counters WHERE scope_id=$1),0),
			COALESCE((SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1),0)`,
		scopeID, name, key, requestID).
		Scan(&forwards, &writes, &audits, &automaticRequests, &intents, &publishVersion, &sourceRevision); err != nil {
		t.Fatalf("load rolled-back L4 facts: %v", err)
	}
	if forwards != 0 || writes != 0 || audits != 0 || automaticRequests != 0 ||
		intents != wantIntents || publishVersion != wantPublishVersion || sourceRevision != wantSourceRevision {
		t.Fatalf("rolled-back facts forward/write/audit/automatic/intent/version/source = %d/%d/%d/%d/%d/%d/%d, want 0/0/0/0/%d/%d/%d",
			forwards, writes, audits, automaticRequests, intents, publishVersion, sourceRevision,
			wantIntents, wantPublishVersion, wantSourceRevision)
	}
}

// seedL4PackageCNAME gives the tenant's package a shared CNAME allocation
// whose LKG hostname is hostname (replica: the DNS provider/zone/job rows the
// foreign keys name are not part of this flow).
func seedL4PackageCNAME(t *testing.T, pool *pgxpool.Pool, tenant l4TenantFixture, hostname string) {
	t.Helper()
	allocation, claim := uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions
			SET product_snapshot=jsonb_set(product_snapshot,'{spec,cname,mode}','"shared"')
			WHERE tenant_scope_id=$1 AND id=$2`, tenant.scopeID, tenant.subscriptionID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO cname_allocations(id,tenant_id,tenant_scope_id,owner_user_id,mode,
			package_subscription_id,current_claim_id,lkg_claim_id,current_revision,lkg_revision,generation,state,job_id,created_at,updated_at)
			SELECT $1,scope.tenant_id,scope.id,$3,'package',$4,$5,$5,1,1,1,'done',gen_random_uuid(),now(),now()
			FROM access_scopes scope WHERE scope.id=$2`,
			allocation, tenant.scopeID, tenant.userID, tenant.subscriptionID, claim); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO cname_hostname_claims(id,tenant_scope_id,allocation_id,generation,provider_id,
			zone_id,domain,hostname,explicit_hostname,hmac_key_id,created_at)
			VALUES($1,$2,$3,1,gen_random_uuid(),gen_random_uuid(),'edge.example',$4,false,'test-key',now())`,
			claim, tenant.scopeID, allocation, hostname)
		return err
	}); err != nil {
		t.Fatalf("seed L4 package CNAME: %v", err)
	}
}

func insertL4Tenant(t *testing.T, pool *pgxpool.Pool, displayName, username, passwordHash string, permissions []string) l4TenantFixture {
	t.Helper()
	tenantID, scopeID, ownerRoleID, viewerRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1, $2)`, tenantID, displayName); err != nil {
		t.Fatalf("insert L4 tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, scopeID, tenantID); err != nil {
		t.Fatalf("insert L4 tenant scope: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO roles (id, scope_id, name, description, system_role) VALUES
			($1, $3, 'tenant_owner', 'L4 tenant owner', true),
			($2, $3, 'tenant_viewer', 'L4 tenant viewer', true)`, ownerRoleID, viewerRoleID, scopeID); err != nil {
		t.Fatalf("insert L4 tenant system roles: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_name)
		SELECT role.id, permission.name
		FROM roles role
		JOIN permissions permission ON
			(role.name = 'tenant_owner' AND permission.name IN ('streams.read', 'streams.manage')) OR
			(role.name = 'tenant_viewer' AND permission.name = 'streams.read')
		WHERE role.scope_id=$1 AND role.system_role
		ON CONFLICT DO NOTHING`, scopeID); err != nil {
		t.Fatalf("grant L4 tenant system role permissions: %v", err)
	}
	userID := insertL4ScopeUser(t, pool, scopeID, username, displayName, passwordHash, permissions)
	return l4TenantFixture{
		scopeID: scopeID, userID: userID,
		subscriptionID: insertL4PackageSubscription(t, pool, scopeID, userID),
		siteID:         insertL4Site(t, pool, scopeID, userID, username),
	}
}

func insertL4Site(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	origin := "192.0.2.200"
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		// display_id 由按 scope 分配的序列给出，站点夹具必须先取号再插入。
		if _, err := tx.Exec(t.Context(), `
			WITH allocated AS (
				INSERT INTO site_display_id_sequences(scope_id, next_value, updated_at)
				VALUES($1, 2, now())
				ON CONFLICT(scope_id) DO UPDATE SET
					next_value=site_display_id_sequences.next_value+1,
					updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			)
			INSERT INTO sites (
				id, display_id, scope_id, owner_user_id, domain, http_ports, origins, origin_hosts,
				created_by_user_id, updated_by_user_id
			) SELECT $2, allocated.display_id, $1, $3, $4, ARRAY['18080']::text[],
			         ARRAY[$5]::text[], ARRAY[$5]::text[], $3, $3
			FROM allocated`,
			scopeID, siteID, userID, domain+".l4.example", origin); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools (site_id) VALUES ($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `
			INSERT INTO site_origins (site_id, position, host, port) VALUES ($1, 1, $2, 80)`, siteID, origin)
		return err
	})
	if err != nil {
		t.Fatalf("insert L4 site fixture: %v", err)
	}
	return siteID
}

func insertL4PackageSubscription(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	return insertL4PackageSubscriptionWithStreamPorts(t, pool, scopeID, userID, 10)
}

// insertL4PackageSubscriptionWithStreamPorts sets limits.stream_ports (-1 is
// unlimited); since b2d72c9d every primary and extra listener consumes one.
func insertL4PackageSubscriptionWithStreamPorts(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, streamPorts int) uuid.UUID {
	t.Helper()
	return insertPackageSubscriptionWithSpec(t, pool, scopeID, userID, func(groupID uuid.UUID) string {
		return strings.Replace(validL4HTTPPackageSpec(groupID), `"stream_ports":10`, fmt.Sprintf(`"stream_ports":%d`, streamPorts), 1)
	})
}

// insertPackageSubscriptionWithSpec creates an active subscription whose product
// spec is built from the generated package group ID.
func insertPackageSubscriptionWithSpec(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, specFor func(groupID uuid.UUID) string) uuid.UUID {
	t.Helper()
	groupID, productID, subscriptionID, platformScopeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	spec := specFor(groupID)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind)
			SELECT $1,'platform' WHERE NOT EXISTS(SELECT 1 FROM access_scopes WHERE kind='platform')`,
			platformScopeID); err != nil {
			return err
		}
		if err := tx.QueryRow(t.Context(), `SELECT id FROM access_scopes
			WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
			return err
		}
		var durableCatalog bool
		if err := tx.QueryRow(t.Context(), `SELECT to_regclass('package_catalog_commit_watermark_090') IS NOT NULL`).Scan(
			&durableCatalog); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_groups(
			id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,true,1,1,$3,$3,clock_timestamp(),clock_timestamp())`,
			groupID, "L4 HTTP "+subscriptionID.String(), userID); err != nil {
			return err
		}
		if durableCatalog {
			if err := insertL4PackageCatalogAuditHTTP(t.Context(), tx, platformScopeID, userID,
				"package.group.create", "package_group", groupID, `{"revision":1,"visible":true}`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(
			id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,true,1,$3::jsonb,1,$4,$4,clock_timestamp(),clock_timestamp())`,
			productID, "L4 HTTP "+subscriptionID.String(), spec, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			VALUES($1,1,$2,true,1,$3::jsonb,false,$4,clock_timestamp())`,
			productID, "L4 HTTP "+subscriptionID.String(), spec, userID); err != nil {
			return err
		}
		if durableCatalog {
			if err := insertL4PackageCatalogAuditHTTP(t.Context(), tx, platformScopeID, userID,
				"package.product.create", "package_product", productID, `{"revision":1,"enabled":true}`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `WITH moment AS (SELECT clock_timestamp() AS now)
			INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,
			custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
			SELECT $1,$2,p.product_id,p.revision,
			jsonb_build_object('id',p.product_id::text,'revision',p.revision,'name',p.name,'spec',p.spec),
			10,10,10,-1,moment.now-interval '1 hour',moment.now+interval '1 day','UTC','monthly',0,1,1,
			'active',1,$3,$3,moment.now,moment.now
			FROM package_product_versions p CROSS JOIN moment WHERE p.product_id=$4 AND p.revision=1`,
			subscriptionID, scopeID, userID, productID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(
			subscription_id,revision,supersedes_subscription_id,supersedes_revision,
			tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
			tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
			entitlement_status,source_order_id,operation,created_by_user_id,created_at)
			SELECT subscription.id,1,NULL,NULL,subscription.tenant_scope_id,subscription.starts_at,NULL,
			subscription.product_id,subscription.product_revision,subscription.product_snapshot,
			subscription.site_limit,subscription.domain_limit,subscription.node_limit,subscription.traffic_limit_bytes,
			subscription.timezone,subscription.cycle_kind,subscription.custom_cycle_days,
			subscription.tcp_factor_numerator,subscription.tcp_factor_denominator,NULL,NULL,'CNY',
			'active',NULL,'migration_backfill',$2,clock_timestamp()
			FROM package_subscriptions subscription WHERE subscription.id=$1`, subscriptionID, userID)
		return err
	})
	if err != nil {
		t.Fatalf("insert L4 package subscription fixture: %v", err)
	}
	return subscriptionID
}

func insertL4PackageCatalogAuditHTTP(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID, actorUserID uuid.UUID,
	action, resourceType string,
	resourceID uuid.UUID,
	payload string,
) error {
	// 走真实审计链写入：全零 event_hash 会让同一平台 scope 的链校验失败。
	var fields map[string]any
	if err := json.Unmarshal([]byte(payload), &fields); err != nil {
		return err
	}
	_, err := audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: platformScopeID, ActorUserID: &actorUserID, Action: action, ResourceType: resourceType,
		ResourceID: resourceID.String(), RequestID: "l4-http-catalog-" + uuid.NewString(), Result: "success", Payload: fields,
	})
	return err
}

func validL4HTTPPackageSpec(groupID uuid.UUID) string {
	return `{"name":"L4 HTTP product","description":"integration","group_ids":["` + groupID.String() + `"],` +
		`"region_id":"11111111-1111-4111-8111-111111111111","node_group_id":"22222222-2222-4222-8222-222222222222","backup_node_group_id":null,` +
		`"limits":{"monthly_traffic_bytes":1024,"bandwidth_bps":1024,"connections":100,"stream_ports":10,"domains":10,"root_domains":10,"http_ports":10,"custom_cc":false,"websocket":true,"http3":true,"l2_origin":false},` +
		`"protection":{"cc":"","ddos":""},"prices":{"currency":"CNY","monthly_minor":100,"quarterly_minor":270,"yearly_minor":1000},` +
		`"cname":{"hostname":"","domain":"cdn.example.com","mode":"per_site"},"purchase":{"per_user_limit":-1,"sale_expires_at":null,"require_real_name":false,"restrict_source_ips":false,"renew_before_days":-1},` +
		`"commercial_terms":{"timezone":"UTC","cycle_kind":"monthly","custom_cycle_days":0,"site_limit":10,"node_limit":10,"tcp_factor_numerator":1,"tcp_factor_denominator":1},"sort_order":1,"enabled":true}`
}

func insertL4ScopeUser(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	username, displayName, passwordHash string,
	permissions []string,
) uuid.UUID {
	t.Helper()
	roleName := ""
	switch {
	case permissions == nil:
	case len(permissions) == 2 && permissions[0] == "streams.read" && permissions[1] == "streams.manage":
		roleName = "tenant_owner"
	case len(permissions) == 1 && permissions[0] == "streams.read":
		roleName = "tenant_viewer"
	default:
		t.Fatalf("unsupported L4 fixture permissions for %q: %#v", username, permissions)
	}
	userID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, $3, $4)`,
		userID, username, displayName, passwordHash); err != nil {
		t.Fatalf("insert L4 scope user %q: %v", username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`, scopeID, userID); err != nil {
		t.Fatalf("insert L4 membership %q: %v", username, err)
	}
	if roleName == "" {
		return userID
	}
	var roleID uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT id FROM roles WHERE scope_id=$1 AND name=$2 AND system_role`, scopeID, roleName).Scan(&roleID); err != nil {
		t.Fatalf("load L4 system role %q for %q: %v", roleName, username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`,
		scopeID, userID, roleID); err != nil {
		t.Fatalf("assign L4 system role %q to %q: %v", roleName, username, err)
	}
	return userID
}

func validStreamFields(tenant l4TenantFixture, name, protocol string, port uint16, upstream string) l4forward.Fields {
	return l4forward.Fields{
		PackageSubscriptionID: new(tenant.subscriptionID), MaxConnectionsPerClient: 100,
		Name: name, Protocol: protocol, ListenAddress: "*", ListenPort: port,
		UpstreamAddress: upstream, UpstreamPort: 9000, ConnectTimeoutMS: 3000,
		ResponseTimeoutMS: 30000, ProxyProtocolV1: protocol == l4forward.ProtocolTCP, Enabled: true,
	}
}

func createL4Forward(t *testing.T, client *http.Client, baseURL, token, key string, body createStreamRequest) l4forward.Forward {
	t.Helper()
	response := l4Request(t, client, http.MethodPost, baseURL+"/v1/streams", body, token, key, "")
	var item l4forward.Forward
	decodeResponse(t, response, http.StatusCreated, &item)
	response.Body.Close()
	return item
}

func updateL4Forward(t *testing.T, client *http.Client, baseURL string, id uuid.UUID, token, key string, body updateStreamRequest, revision int64) l4forward.Forward {
	t.Helper()
	response := l4Request(t, client, http.MethodPatch, baseURL+"/v1/streams/"+id.String(), body, token, key, `"`+strconv.FormatInt(revision, 10)+`"`)
	var item l4forward.Forward
	decodeResponse(t, response, http.StatusOK, &item)
	response.Body.Close()
	return item
}

func getL4Forward(t *testing.T, client *http.Client, baseURL string, id uuid.UUID, token string) l4forward.Forward {
	t.Helper()
	response := l4Request(t, client, http.MethodGet, baseURL+"/v1/streams/"+id.String(), nil, token, "", "")
	var item l4forward.Forward
	decodeResponse(t, response, http.StatusOK, &item)
	response.Body.Close()
	return item
}

func listL4Forwards(t *testing.T, client *http.Client, rawURL, token string) l4forward.ListResult {
	t.Helper()
	response := l4Request(t, client, http.MethodGet, rawURL, nil, token, "", "")
	var result l4forward.ListResult
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	return result
}

func l4Request(t *testing.T, client *http.Client, method, rawURL string, body any, token, key, ifMatch string) *http.Response {
	t.Helper()
	response, err := performL4Request(client, method, rawURL, body, token, key, ifMatch)
	if err != nil {
		t.Fatalf("perform L4 request: %v", err)
	}
	return response
}

func performL4Request(client *http.Client, method, rawURL string, body any, token, key, ifMatch string, requestIDs ...string) (*http.Response, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	request, err := http.NewRequest(method, rawURL, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if len(requestIDs) > 0 {
		request.Header.Set("X-Request-ID", requestIDs[0])
	}
	return client.Do(request)
}

// TestL4NewConnectionRateHTTP: 单 IP 新建连接速率 through the HTTP API.
func TestL4NewConnectionRateHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenant := insertL4Tenant(t, pool, "Rate Tenant", "rate-owner", passwordHash, []string{"streams.read", "streams.manage"})
	tokens, err := identity.NewTokenManager("l4-integration-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	ownerAuth, _ := loginOK(t, client, server.URL, "rate-owner")
	installL4AutomaticPolicy(t, pool, tenant)
	// 单 IP 新建连接速率: stored, returned and carried by the intent; burst
	// without a rate is refused.
	rated := validStreamFields(tenant, "Rated UDP", l4forward.ProtocolUDP, 18170, "192.0.2.13")
	rated.MaxNewConnectionsPerClientPerSecond, rated.NewConnectionBurst, rated.NewConnectionBanSeconds = 20, 5, 60
	createdRated := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "create-rated", createStreamRequest{Fields: rated})
	if createdRated.MaxNewConnectionsPerClientPerSecond != 20 || createdRated.NewConnectionBurst != 5 || createdRated.NewConnectionBanSeconds != 60 ||
		createdRated.PublishIntent.RuntimeSpec.NewConnRate == nil || createdRated.PublishIntent.RuntimeSpec.NewConnRate.RatePerSecond != 20 {
		t.Fatalf("created rated rule = %#v", createdRated)
	}
	if readRated := getL4Forward(t, client, server.URL, createdRated.ID, ownerAuth.AccessToken); readRated.NewConnectionBanSeconds != 60 ||
		readRated.PublishIntent.RuntimeSpec.NewConnRate == nil {
		t.Fatalf("read rated rule = %#v", readRated)
	}
	plain := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "create-unrated", createStreamRequest{
		Fields: validStreamFields(tenant, "Unrated TCP", l4forward.ProtocolTCP, 18172, "192.0.2.15")})
	if plain.PublishIntent.RuntimeSpec.NewConnRate != nil || plain.MaxNewConnectionsPerClientPerSecond != 0 {
		t.Fatalf("unlimited rule carries a rate: %#v", plain.PublishIntent.RuntimeSpec.NewConnRate)
	}
	burstOnly := validStreamFields(tenant, "Burst only", l4forward.ProtocolTCP, 18171, "192.0.2.14")
	burstOnly.NewConnectionBurst = 5
	response := l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: burstOnly}, ownerAuth.AccessToken, "burst-only", "")
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()
}
