package httpapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

func TestL4StreamListFiltersHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "filter-admin", "Filter Admin", passwordHash, "bootstrap-filter-admin"); err != nil {
		t.Fatal(err)
	}
	tenant := insertL4Tenant(t, pool, "Filter Tenant", "filter-owner", passwordHash, []string{"streams.read", "streams.manage"})
	other := insertL4Tenant(t, pool, "Filter Other", "filter-other", passwordHash, []string{"streams.read", "streams.manage"})
	viewerID := insertL4ScopeUser(t, pool, tenant.scopeID, "filter-viewer", "Filter Viewer", passwordHash, []string{"streams.read"})
	tokens, err := identity.NewTokenManager("l4-filter-integration-test-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	adminAuth, _ := loginOK(t, client, server.URL, "filter-admin")
	ownerAuth, _ := loginOK(t, client, server.URL, "filter-owner")
	otherAuth, _ := loginOK(t, client, server.URL, "filter-other")
	viewerAuth, _ := loginOK(t, client, server.URL, "filter-viewer")
	installL4AutomaticPolicy(t, pool, tenant)
	installL4AutomaticPolicy(t, pool, other)
	group := createStreamGroup(t, client, server.URL, ownerAuth.AccessToken, "filter-group", streamGroupRequest{Name: "筛选分组"})
	otherGroup := createStreamGroup(t, client, server.URL, otherAuth.AccessToken, "filter-other-group", streamGroupRequest{Name: "其他租户分组"})
	first := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "filter-first", createStreamRequest{
		Fields: validStreamFields(tenant, "UDP alpha", "udp", 18100, "192.0.2.10"), GroupIDs: []string{group.ID.String()},
	})
	domainFields := validStreamFields(tenant, "TCP beta", "tcp", 18101, "")
	domainFields.UpstreamHost = "origin.example.com"
	domainFields.DNS.PositiveMinTTLSeconds = 1
	domainFields.DNS.PositiveMaxTTLSeconds = 300
	domainFields.DNS.NegativeTTLSeconds = 30
	domainFields.DNS.StaleIfErrorSeconds = 300
	domainFields.Enabled = false
	second := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "filter-second", createStreamRequest{Fields: domainFields})
	secondPackage := tenant
	secondPackage.subscriptionID = insertL4PackageSubscription(t, pool, tenant.scopeID, tenant.userID)
	third := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "filter-third", createStreamRequest{
		Fields: validStreamFields(secondPackage, "TCP gamma", "tcp", 18102, "2001:db8::10"), GroupIDs: []string{group.ID.String()},
	})
	// 归属人必须是套餐持有人（l4forward/package_limits.go 的 OwnerUserID 校验），viewer 用自己的套餐。
	viewerFields := validStreamFields(tenant, "Viewer stream", "tcp", 18103, "192.0.2.10")
	viewerFields.PackageSubscriptionID = new(insertL4PackageSubscription(t, pool, tenant.scopeID, viewerID))
	viewerOwned := createL4Forward(t, client, server.URL, adminAuth.AccessToken, "filter-viewer-stream", createStreamRequest{
		TargetScopeID: tenant.scopeID.String(), OwnerID: viewerID.String(), GroupIDs: []string{group.ID.String()},
		Fields: viewerFields,
	})
	foreign := createL4Forward(t, client, server.URL, otherAuth.AccessToken, "filter-foreign", createStreamRequest{
		Fields: validStreamFields(other, "Foreign stream", "tcp", 18200, "192.0.2.10"), GroupIDs: []string{otherGroup.ID.String()},
	})
	var productID, otherProductID, viewerProductID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT product_id FROM package_subscriptions WHERE id=$1 AND tenant_scope_id=$2`, viewerFields.PackageSubscriptionID, tenant.scopeID).Scan(&viewerProductID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT product_id FROM package_subscriptions WHERE id=$1 AND tenant_scope_id=$2`, tenant.subscriptionID, tenant.scopeID).Scan(&productID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT product_id FROM package_subscriptions WHERE id=$1 AND tenant_scope_id=$2`, other.subscriptionID, other.scopeID).Scan(&otherProductID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query, token string
		want               []uuid.UUID
		total              int64
	}{
		{"listen port", "listen_port=18100", ownerAuth.AccessToken, []uuid.UUID{first.ID}, 1},
		{"listen port exact", "listen_port=181", ownerAuth.AccessToken, nil, 0},
		{"minimum port", "listen_port=1", ownerAuth.AccessToken, nil, 0},
		{"maximum port", "listen_port=65535", ownerAuth.AccessToken, nil, 0},
		{"IPv4 substring", "upstream=192.0.2", ownerAuth.AccessToken, []uuid.UUID{first.ID}, 1},
		{"IPv6 substring", "upstream=db8", ownerAuth.AccessToken, []uuid.UUID{third.ID}, 1},
		{"domain case insensitive", "upstream=ORIGIN.EXAMPLE", ownerAuth.AccessToken, []uuid.UUID{second.ID}, 1},
		{"literal percent", "upstream=%25", ownerAuth.AccessToken, nil, 0},
		{"literal underscore", "upstream=_", ownerAuth.AccessToken, nil, 0},
		{"literal backslash", "upstream=%5C", ownerAuth.AccessToken, nil, 0},
		{"display ID", "display_id=" + second.DisplayID, ownerAuth.AccessToken, []uuid.UUID{second.ID}, 1},
		{"missing display ID", "display_id=9223372036854775807", ownerAuth.AccessToken, nil, 0},
		{"group owner isolation", "group_id=" + group.ID.String(), ownerAuth.AccessToken, []uuid.UUID{first.ID, third.ID}, 2},
		{"group viewer isolation", "group_id=" + group.ID.String(), viewerAuth.AccessToken, []uuid.UUID{viewerOwned.ID}, 1},
		{"foreign group", "group_id=" + otherGroup.ID.String(), ownerAuth.AccessToken, nil, 0},
		{"missing group", "group_id=" + uuid.NewString(), ownerAuth.AccessToken, nil, 0},
		{"package", "package_product_id=" + productID.String(), ownerAuth.AccessToken, []uuid.UUID{first.ID, second.ID}, 2},
		{"foreign package", "package_product_id=" + otherProductID.String(), ownerAuth.AccessToken, nil, 0},
		{"missing package", "package_product_id=" + uuid.NewString(), ownerAuth.AccessToken, nil, 0},
		{"subscription is not product", "package_product_id=" + tenant.subscriptionID.String(), ownerAuth.AccessToken, nil, 0},
		{"other tenant", "package_product_id=" + otherProductID.String(), otherAuth.AccessToken, []uuid.UUID{foreign.ID}, 1},
		{"combined", "listen_port=18100&upstream=192.0&display_id=" + first.DisplayID + "&group_id=" + group.ID.String() + "&package_product_id=" + productID.String() + "&protocol=udp&enabled=true&search=alpha", ownerAuth.AccessToken, []uuid.UUID{first.ID}, 1},
		{"contradictory filters", "listen_port=18100&protocol=tcp", ownerAuth.AccessToken, nil, 0},
		{"page one", "package_product_id=" + productID.String() + "&page=1&limit=1", ownerAuth.AccessToken, []uuid.UUID{second.ID}, 2},
		{"page two", "package_product_id=" + productID.String() + "&page=2&limit=1", ownerAuth.AccessToken, []uuid.UUID{first.ID}, 2},
		{"empty page retains total", "package_product_id=" + productID.String() + "&page=3&limit=1", ownerAuth.AccessToken, nil, 2},
		{"platform package", "package_product_id=" + productID.String(), adminAuth.AccessToken, []uuid.UUID{first.ID, second.ID}, 2},
		{"platform other owner package", "package_product_id=" + viewerProductID.String(), adminAuth.AccessToken, []uuid.UUID{viewerOwned.ID}, 1},
		{"owner cannot see viewer package", "package_product_id=" + viewerProductID.String(), ownerAuth.AccessToken, nil, 0},
		{"legacy search", "search=gamma", ownerAuth.AccessToken, []uuid.UUID{third.ID}, 1},
		{"maximum upstream length", "upstream=" + strings.Repeat("a", 253), ownerAuth.AccessToken, nil, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := listL4Forwards(t, client, server.URL+"/v1/streams?"+test.query, test.token)
			if result.Total != test.total || len(result.Items) != len(test.want) {
				t.Fatalf("filtered list = %+v, want IDs %v total %d", result, test.want, test.total)
			}
			wanted := make(map[uuid.UUID]bool, len(test.want))
			for _, id := range test.want {
				wanted[id] = true
			}
			for _, item := range result.Items {
				if !wanted[item.ID] {
					t.Errorf("unexpected stream %s", item.ID)
				}
				delete(wanted, item.ID)
			}
			if len(wanted) != 0 {
				t.Errorf("missing streams %v", wanted)
			}
		})
	}
	t.Run("owner display number and exact publication observation", func(t *testing.T) {
		var ownerDisplayID, viewerDisplayID, otherDisplayID string
		for id, target := range map[uuid.UUID]*string{tenant.userID: &ownerDisplayID, viewerID: &viewerDisplayID, other.userID: &otherDisplayID} {
			if err := pool.QueryRow(t.Context(), `SELECT display_id::text FROM users WHERE id=$1`, id).Scan(target); err != nil {
				t.Fatal(err)
			}
		}
		response := l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+first.ID.String(), updateStreamRequest{
			ExpectedRevision: first.Revision, Fields: validStreamFields(tenant, "UDP alpha current", "udp", 18100, "192.0.2.10"),
		}, ownerAuth.AccessToken, "filter-current-intent", fmt.Sprintf(`"%d"`, first.Revision))
		decodeResponse(t, response, http.StatusOK, &first)
		response.Body.Close()
		var firstRequestID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT id FROM edge_automatic_publication_requests WHERE publish_intent_id=$1`, first.PublishIntent.ID).Scan(&firstRequestID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
			(request_id,sequence,state,attempt,lease_owner,lease_token,lease_expires_at,occurred_at)
			VALUES($1,2,'leased',1,'filter-test',$2,clock_timestamp()+interval '1 minute',clock_timestamp())`, firstRequestID, uuid.New()); err != nil {
			t.Fatal(err)
		}
		leased := listL4Forwards(t, client, server.URL+"/v1/streams?publication_state=leased", ownerAuth.AccessToken)
		if leased.Total != 1 || len(leased.Items) != 1 || leased.Items[0].ID != first.ID || leased.Items[0].PublishIntent.State != "leased" {
			t.Fatalf("leased observation = %+v", leased)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
			(request_id,sequence,state,attempt,available_at,error_class,occurred_at)
			VALUES($1,3,'retry_wait',1,clock_timestamp()+interval '1 minute','publish_outcome_unknown',clock_timestamp())`, firstRequestID); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name, query, token string
			want               []uuid.UUID
			total              int64
		}{
			{"platform owner number", "owner_display_id=" + ownerDisplayID, adminAuth.AccessToken, []uuid.UUID{first.ID, second.ID, third.ID}, 3},
			{"own number", "owner_display_id=" + ownerDisplayID, ownerAuth.AccessToken, []uuid.UUID{first.ID, second.ID, third.ID}, 3},
			{"same scope other owner", "owner_display_id=" + viewerDisplayID, ownerAuth.AccessToken, nil, 0},
			{"foreign owner", "owner_display_id=" + otherDisplayID, ownerAuth.AccessToken, nil, 0},
			{"viewer own", "owner_display_id=" + viewerDisplayID, viewerAuth.AccessToken, []uuid.UUID{viewerOwned.ID}, 1},
			{"platform viewer", "owner_display_id=" + viewerDisplayID, adminAuth.AccessToken, []uuid.UUID{viewerOwned.ID}, 1},
			{"missing number", "owner_display_id=9223372036854775807", adminAuth.AccessToken, nil, 0},
			{"retrying mapping", "publication_state=retrying", ownerAuth.AccessToken, []uuid.UUID{first.ID}, 1},
			{"latest state only", "publication_state=leased", ownerAuth.AccessToken, nil, 0},
			{"pending owner isolation", "publication_state=pending", ownerAuth.AccessToken, nil, 0},
			{"pending other scope", "publication_state=pending", otherAuth.AccessToken, []uuid.UUID{foreign.ID}, 1},
			{"superseded", "publication_state=superseded", ownerAuth.AccessToken, []uuid.UUID{second.ID, third.ID}, 2},
			{"combined", "owner_display_id=" + ownerDisplayID + "&publication_state=retrying&protocol=udp&enabled=true&listen_port=18100&upstream=192.0", adminAuth.AccessToken, []uuid.UUID{first.ID}, 1},
			{"AND contradiction", "publication_state=retrying&enabled=false", ownerAuth.AccessToken, nil, 0},
			{"owner page two", "owner_display_id=" + ownerDisplayID + "&page=2&limit=1", adminAuth.AccessToken, []uuid.UUID{second.ID}, 3},
			{"state empty page retains count", "publication_state=retrying&page=2&limit=1", ownerAuth.AccessToken, nil, 1},
		} {
			t.Run(test.name, func(t *testing.T) {
				result := listL4Forwards(t, client, server.URL+"/v1/streams?"+test.query, test.token)
				if result.Total != test.total || len(result.Items) != len(test.want) {
					t.Fatalf("filtered list=%+v want=%v total=%d", result, test.want, test.total)
				}
				wanted := make(map[uuid.UUID]bool)
				for _, id := range test.want {
					wanted[id] = true
				}
				for _, item := range result.Items {
					if !wanted[item.ID] {
						t.Fatalf("unexpected stream %s", item.ID)
					}
					values, _ := url.ParseQuery(test.query)
					if state := values.Get("publication_state"); state != "" && item.PublishIntent.State != state {
						t.Fatalf("filter %s disagrees with returned state %s", state, item.PublishIntent.State)
					}
				}
			})
		}
		response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+first.ID.String(), updateStreamRequest{
			ExpectedRevision: first.Revision, Fields: validStreamFields(tenant, "UDP alpha updated", "udp", 18100, "192.0.2.10"),
		}, ownerAuth.AccessToken, "filter-latest-intent", fmt.Sprintf(`"%d"`, first.Revision))
		var updated l4forward.Forward
		decodeResponse(t, response, http.StatusOK, &updated)
		response.Body.Close()
		result := listL4Forwards(t, client, server.URL+"/v1/streams?publication_state=retrying", ownerAuth.AccessToken)
		if result.Total != 0 || len(result.Items) != 0 {
			t.Fatalf("previous intent state leaked into current filter: %+v", result)
		}
		unknownTenant := insertL4Tenant(t, pool, "Unknown Filter Tenant", "unknown-filter-owner", passwordHash, []string{"streams.read", "streams.manage"})
		unknownAuth, _ := loginOK(t, client, server.URL, "unknown-filter-owner")
		unknown := createL4Forward(t, client, server.URL, unknownAuth.AccessToken, "unknown-state", createStreamRequest{Fields: validStreamFields(unknownTenant, "Unknown", "udp", 18300, "192.0.2.20")})
		result = listL4Forwards(t, client, server.URL+"/v1/streams?publication_state=unknown", unknownAuth.AccessToken)
		if result.Total != 1 || len(result.Items) != 1 || result.Items[0].ID != unknown.ID || result.Items[0].PublishIntent.State != "unknown" {
			t.Fatalf("missing observation must remain unknown: %+v", result)
		}
	})
	invalid := []string{
		"protocol=", "protocol=TCP", "protocol=+tcp", "protocol=http", "enabled=", "enabled=1", "enabled=TRUE", "enabled=false+",
		"owner_display_id=", "owner_display_id=0", "owner_display_id=01", "owner_display_id=" + tenant.userID.String(),
		"owner_display_id=9223372036854775808", "owner_display_id=1&owner_display_id=1",
		"publication_state=", "publication_state=retry_wait", "publication_state=normal", "publication_state=pending&publication_state=failed",
		"listen_port=1&listen_port=1", "search=a&search=b", "unknown_filter=1",
		"listen_port=0", "listen_port=65536", "listen_port=-1", "listen_port=1.5", "listen_port=", "listen_port=01", "listen_port=18100&listen_port=18101",
		"display_id=0", "display_id=-1", "display_id=9223372036854775808", "display_id=", "display_id=01", "display_id=1&display_id=2",
		"group_id=bad", "group_id=", "group_id=" + uuid.Nil.String(), "group_id=" + group.ID.String() + "&group_id=" + group.ID.String(),
		"package_product_id=bad", "package_product_id=", "package_product_id=" + uuid.Nil.String(), "package_product_id=" + productID.String() + "&package_product_id=" + productID.String(),
		"upstream=", "upstream=+", "upstream=a&upstream=b", "upstream=" + strings.Repeat("a", 254), "upstream=%00", "upstream=%FF", "upstream=%zz",
	}
	for _, query := range invalid {
		t.Run("invalid/"+url.QueryEscape(query), func(t *testing.T) {
			response := l4Request(t, client, http.MethodGet, server.URL+"/v1/streams?"+query, nil, ownerAuth.AccessToken, "", "")
			assertError(t, response, http.StatusBadRequest, "validation_error", "")
			response.Body.Close()
		})
	}
}
