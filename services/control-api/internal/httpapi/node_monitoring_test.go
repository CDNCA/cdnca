package httpapi

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeMonitoringLatest(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	admin, err := identityStore.BootstrapPlatformUser(t.Context(), "probeadmin", "Probe Admin", passwordHash, "monitoring-batch-test")
	if err != nil {
		t.Fatal(err)
	}
	readerUser := insertTestUser(t, pool, admin.ScopeID, "probereader", "Probe Reader", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, readerUser, "nodes.read")
	insertTestUser(t, pool, admin.ScopeID, "probeviewer", "Probe Viewer", passwordHash, "active")
	tenantName, tenantScope := insertTenantAdmin(t, pool, passwordHash)
	tokens, err := identity.NewTokenManager("node-monitoring-batch-test-key-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(identityStore, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := nodemetrics.NewPostgresReader(pool)
	api := New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x51}, 32), NodeMetricsReader: reader})
	server := monitoringHTTPServer(api)
	t.Cleanup(server.Close)
	client := server.Client()
	readerAuth, _ := loginOK(t, client, server.URL, "probereader")
	viewerAuth, _ := loginOK(t, client, server.URL, "probeviewer")
	tenantAuth := loginForScope(t, client, server.URL, tenantName, tenantScope)
	ids := make([]uuid.UUID, 300)
	query := "?"
	for index := range ids {
		ids[index] = uuid.New()
		query += "node_id=" + ids[index].String() + "&"
	}
	query = strings.TrimSuffix(query, "&")
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		SELECT id,$2,'http-probe-' || position,'active',$3,position FROM unnest($1::uuid[]) WITH ORDINALITY requested(id,position)`, ids, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	foreign := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'foreign-probe',$3,1)`, foreign, tenantScope, admin.UserID); err != nil {
		t.Fatal(err)
	}
	store, _ := nodemetrics.NewPostgresStore(pool)
	observed := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	for index, id := range ids[:2] {
		sample := nodemetrics.Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: id.String(), SchemaVersion: 1,
			PublicationSequence: 1, ObservedAt: observed, Kind: nodemetrics.RecordHostMetric, Known: true, MemoryTotalBytes: 2,
			PubAckStream: nodemetrics.NodeMonitoringStatusStream, PubAckSequence: uint64(index + 1), ConsumerDurable: nodemetrics.DefaultConsumerDurable,
			ConsumerSequence: uint64(index + 1), NumDelivered: 1, WireSHA256: sha256.Sum256([]byte(fmt.Sprintf("synthetic-http-probe-%d", index)))}
		if index == 1 {
			sample.Kind, sample.ConfigRevision, sample.ActiveConfigRevision, sample.ProbePort = nodemetrics.RecordMetric, 1, 1, 80
			sample.Known, sample.MemoryTotalBytes = false, 0
		}
		if _, err := store.Put(t.Context(), sample); err != nil {
			t.Fatal(err)
		}
	}
	path := "/v1/nodes/monitoring/latest"
	before := time.Now().UTC()
	response := doRequest(t, client, http.MethodGet, server.URL+path+query, nil, nil, readerAuth.AccessToken)
	var result nodemetrics.MonitoringSnapshot
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	if result.SchemaVersion != 1 || result.ObservedAt.Before(before) || result.ObservedAt.After(time.Now().UTC()) || result.ObservedAt.Location() != time.UTC || len(result.Items) != 300 || result.Configuration.State != "unconfigured" {
		t.Fatalf("batch shape/read time: %+v", result)
	}
	for index, item := range result.Items {
		if item.NodeID != ids[index] {
			t.Fatal("request ordering changed")
		}
	}
	if result.Items[0].Sample != nil || result.Items[0].Freshness != "not_reported" || result.Items[2].Sample != nil {
		t.Fatal("host-only or missing data invented a probe")
	}
	if sample := result.Items[1].Sample; sample == nil || sample.Source != "agent_local_tcp" || !sample.ObservedAt.Equal(observed) || result.Items[1].Freshness != "stale" || result.Items[1].RevisionState != "unknown" || result.Items[1].StaleAfterMS != nil {
		t.Fatal("old real probe lost without active config")
	}
	response = doRequest(t, client, http.MethodGet, server.URL+path+"?node_id="+ids[1].String(), nil, nil, readerAuth.AccessToken)
	var raw map[string]any
	decodeResponse(t, response, http.StatusOK, &raw)
	response.Body.Close()
	item := raw["items"].([]any)[0].(map[string]any)
	sample := item["sample"].(map[string]any)
	if len(raw) != 4 || len(raw["configuration"].(map[string]any)) != 5 || len(item) != 6 || item["delivery_state"] != nodemetrics.DeliveryAwaitingConfiguration || len(sample) != 16 || sample["publication_sequence"] != "1" || sample["probes_total"] != "0" {
		t.Fatalf("noncanonical or excess evidence: %+v", raw)
	}
	for _, test := range []struct {
		token  string
		status int
		code   string
	}{
		{"", http.StatusUnauthorized, "invalid_session"}, {viewerAuth.AccessToken, http.StatusForbidden, "permission_denied"}, {tenantAuth.AccessToken, http.StatusForbidden, "permission_denied"},
	} {
		response := doRequest(t, client, http.MethodGet, server.URL+path+"?node_id="+ids[0].String(), nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
	for _, invalid := range []string{"", "?node_id=", "?node_id=invalid", "?node_id=" + uuid.Nil.String(), "?node_id=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
		"?node_id=" + ids[0].String() + "&node_id=" + ids[0].String(), query + "&extra=1", query + ";ignored=1", query + "&node_id=" + uuid.NewString()} {
		response := doRequest(t, client, http.MethodGet, server.URL+path+invalid, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	for _, absent := range []uuid.UUID{foreign, uuid.New()} {
		response := doRequest(t, client, http.MethodGet, server.URL+path+"?node_id="+ids[1].String()+"&node_id="+absent.String(), nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusNotFound, "node_monitoring_not_found", "")
		response.Body.Close()
	}
	closedPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	closedReader, _ := nodemetrics.NewPostgresReader(closedPool)
	closedPool.Close()
	type legacyMetricsReader struct{ NodeMetricsReader }
	for _, unavailable := range []NodeMetricsReader{nil, closedReader, legacyMetricsReader{reader}} {
		unavailableServer := monitoringHTTPServer(New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x51}, 32), NodeMetricsReader: unavailable}))
		response := doRequest(t, unavailableServer.Client(), http.MethodGet, unavailableServer.URL+path+"?node_id="+ids[0].String(), nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusServiceUnavailable, "node_monitoring_unavailable", "")
		response.Body.Close()
		unavailableServer.Close()
	}
	historyPath := "/v1/nodes/" + ids[1].String() + "/monitoring/history"
	window := "?from=" + observed.Add(-time.Minute).Format(time.RFC3339Nano) + "&to=" + observed.Add(time.Minute).Format(time.RFC3339Nano)
	response = doRequest(t, client, http.MethodGet, server.URL+historyPath+window+"&page=1&limit=10", nil, nil, readerAuth.AccessToken)
	var history nodemetrics.MonitoringHistoryPage
	decodeResponse(t, response, http.StatusOK, &history)
	response.Body.Close()
	if history.NodeID != ids[1] || history.Total != 1 || len(history.Items) != 1 || history.Page != 1 || history.Limit != 10 ||
		!history.Items[0].ObservedAt.Equal(observed) || history.Items[0].TotalChecks != 1 || history.Items[0].ProbePort != 80 {
		t.Fatalf("monitoring history = %+v", history)
	}
	// probe-node: dnspup checkpoints log (source=dnspup, group filter by carrier).
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_dnspup_probe_results(node_id,address,port,observed_at,
		total_checks,failed_checks,failed,checkpoints) VALUES($1,'198.51.100.7',443,$2,3,2,true,
		'[{"id":"t1","group":"telecom","ok":false},{"id":"t2","group":"telecom","ok":false},{"id":"u1","group":"unicom","ok":true}]')`,
		ids[1], observed); err != nil {
		t.Fatal(err)
	}
	var dnspup nodemetrics.DNSPupHistoryPage
	response = doRequest(t, client, http.MethodGet, server.URL+historyPath+window+"&source=dnspup&group=unicom", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &dnspup)
	response.Body.Close()
	if dnspup.Source != "dnspup" || dnspup.Group != "unicom" || dnspup.Total != 1 || len(dnspup.Items) != 1 ||
		dnspup.Items[0].TotalChecks != 1 || dnspup.Items[0].FailedChecks != 0 || dnspup.Items[0].Address != "198.51.100.7" ||
		dnspup.Items[0].Port != 443 || len(dnspup.Items[0].Checkpoints) != 1 {
		t.Fatalf("dnspup monitoring history = %+v", dnspup)
	}
	response = doRequest(t, client, http.MethodGet, server.URL+historyPath+window+"&source=dnspup", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &dnspup)
	response.Body.Close()
	if len(dnspup.Items) != 1 || dnspup.Items[0].TotalChecks != 3 || dnspup.Items[0].FailedChecks != 2 || !dnspup.Items[0].Failed {
		t.Fatalf("dnspup monitoring history all groups = %+v", dnspup)
	}
	// fix-probe: peer probe log (source=peer: controller + peer nodes).
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_peer_probe_results(node_id,address,port,observed_at,
		controller_ok,total_checks,failed_checks,failed,checkpoints) VALUES($1,'198.51.100.7',443,$2,false,2,2,true,
		'[{"id":"controller","ok":false},{"id":"n2","name":"edge-2","address":"198.51.100.8","ok":false,"latency_ms":0}]')`,
		ids[1], observed); err != nil {
		t.Fatal(err)
	}
	var peer nodemetrics.PeerHistoryPage
	response = doRequest(t, client, http.MethodGet, server.URL+historyPath+window+"&source=peer", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &peer)
	response.Body.Close()
	if peer.Source != "peer" || peer.Total != 1 || len(peer.Items) != 1 || !peer.Items[0].Failed ||
		peer.Items[0].ControllerOK == nil || *peer.Items[0].ControllerOK || peer.Items[0].TotalChecks != 2 ||
		len(peer.Items[0].Checkpoints) != 2 || peer.Items[0].Checkpoints[1].Name != "edge-2" {
		t.Fatalf("peer monitoring history = %+v", peer)
	}
	for _, invalid := range []string{"&source=other", "&source=dnspup&group=bgp", "&group=telecom", "&source=dnspup&source=dnspup",
		"&source=peer&group=telecom"} {
		response := doRequest(t, client, http.MethodGet, server.URL+historyPath+window+invalid, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	response = doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+ids[0].String()+"/monitoring/history", nil, nil, readerAuth.AccessToken)
	decodeResponse(t, response, http.StatusOK, &history)
	response.Body.Close()
	if history.Total != 0 || len(history.Items) != 0 || !history.To.After(history.From) || history.To.Sub(history.From) != time.Hour {
		t.Fatalf("host-only node history invented probe rows or default window changed: %+v", history)
	}
	for _, test := range []struct {
		token  string
		status int
		code   string
	}{
		{"", http.StatusUnauthorized, "invalid_session"}, {viewerAuth.AccessToken, http.StatusForbidden, "permission_denied"}, {tenantAuth.AccessToken, http.StatusForbidden, "permission_denied"},
	} {
		response := doRequest(t, client, http.MethodGet, server.URL+historyPath, nil, nil, test.token)
		assertError(t, response, test.status, test.code, "")
		response.Body.Close()
	}
	for _, invalid := range []string{"?page=0", "?page=01", "?limit=101", "?limit=x", "?extra=1", "?page=1&page=2", "?from=yesterday",
		"?from=" + observed.Format(time.RFC3339Nano) + "&to=" + observed.Format(time.RFC3339Nano),
		"?from=" + observed.Add(-8*24*time.Hour).Format(time.RFC3339Nano) + "&to=" + observed.Format(time.RFC3339Nano)} {
		response := doRequest(t, client, http.MethodGet, server.URL+historyPath+invalid, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	}
	response = doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/not-a-uuid/monitoring/history", nil, nil, readerAuth.AccessToken)
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()
	for _, absent := range []uuid.UUID{foreign, uuid.New()} {
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+absent.String()+"/monitoring/history", nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusNotFound, "node_monitoring_not_found", "")
		response.Body.Close()
	}
	for _, unavailable := range []NodeMetricsReader{nil, closedReader, legacyMetricsReader{reader}} {
		unavailableServer := monitoringHTTPServer(New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x51}, 32), NodeMetricsReader: unavailable}))
		response := doRequest(t, unavailableServer.Client(), http.MethodGet, unavailableServer.URL+historyPath, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusServiceUnavailable, "node_monitoring_unavailable", "")
		response.Body.Close()
		unavailableServer.Close()
	}
	unsafe := nodemetrics.Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: ids[1].String(), SchemaVersion: 1, Kind: nodemetrics.RecordMetric,
		ConfigRevision: 1 << 53, ActiveConfigRevision: 1, ProbePort: 80, PublicationSequence: 2, ObservedAt: observed,
		PubAckStream: nodemetrics.NodeMonitoringStatusStream, PubAckSequence: 3, ConsumerDurable: nodemetrics.DefaultConsumerDurable, ConsumerSequence: 3, NumDelivered: 1, WireSHA256: sha256.Sum256([]byte("synthetic-unsafe-probe"))}
	if _, err := store.Put(t.Context(), unsafe); err != nil {
		t.Fatal(err)
	}
	response = doRequest(t, client, http.MethodGet, server.URL+path+"?node_id="+ids[1].String(), nil, nil, readerAuth.AccessToken)
	assertError(t, response, http.StatusServiceUnavailable, "node_monitoring_unavailable", "")
	response.Body.Close()
}

func monitoringHTTPServer(api *Server) *httptest.Server {
	return httptest.NewServer(api.Handler())
}
