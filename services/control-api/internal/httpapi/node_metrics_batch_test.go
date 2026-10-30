package httpapi

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeMetricsLatestBatch(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	admin, err := identityStore.BootstrapPlatformUser(t.Context(), "metricsadmin", "Metrics Admin", passwordHash, "metrics-batch-test")
	if err != nil {
		t.Fatal(err)
	}
	readerUser := insertTestUser(t, pool, admin.ScopeID, "metricsreader", "Metrics Reader", passwordHash, "active")
	grantNodePermissions(t, pool, admin.ScopeID, readerUser, "nodes.read")
	insertTestUser(t, pool, admin.ScopeID, "metricsviewer", "Metrics Viewer", passwordHash, "active")
	tenantName, tenantScope := insertTenantAdmin(t, pool, passwordHash)
	tokens, err := identity.NewTokenManager("node-metrics-batch-test-key-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := identity.NewService(identityStore, tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := nodemetrics.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NodeMetricsReader: reader})
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	readerAuth, _ := loginOK(t, client, server.URL, "metricsreader")
	viewerAuth, _ := loginOK(t, client, server.URL, "metricsviewer")
	tenantAuth := loginForScope(t, client, server.URL, tenantName, tenantScope)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for index, id := range ids {
		scope := admin.ScopeID
		if index == 3 {
			scope = tenantScope
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,$5)`, id, scope, fmt.Sprintf("batch-%d", index), admin.UserID, index+1); err != nil {
			t.Fatal(err)
		}
	}
	store, _ := nodemetrics.NewPostgresStore(pool)
	observed := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for index, id := range ids[:2] {
		sample := nodemetrics.Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: id.String(),
			SchemaVersion: 1, PublicationSequence: 1, ObservedAt: observed, Kind: nodemetrics.RecordHostMetric,
			Known: true, MemoryUsedBytes: 1, MemoryTotalBytes: 2, RXBandwidthBPS: 1600, TXBandwidthBPS: 800,
			PubAckStream: nodemetrics.NodeMonitoringStatusStream, PubAckSequence: uint64(index + 1),
			ConsumerDurable: nodemetrics.DefaultConsumerDurable, ConsumerSequence: uint64(index + 1), NumDelivered: 1,
			WireSHA256: sha256.Sum256([]byte(fmt.Sprintf("synthetic-batch-%d", index))),
			Telemetry: &nodemetrics.Telemetry{SchemaVersion: 1, TotalRXBytes: 300, TotalTXBytes: 600,
				NetworkSelection:  &nodemetrics.NetworkSelection{Source: "default_route", Interfaces: []string{"ens17"}},
				NetworkInterfaces: []nodemetrics.NetworkInterface{{Name: "ens17", RXBytes: 300, TXBytes: 600, RXBandwidthBPS: 1600, TXBandwidthBPS: 800}}},
		}
		if index == 1 {
			sample.Kind, sample.ConfigRevision, sample.ActiveConfigRevision, sample.ProbePort = nodemetrics.RecordMetric, 7, 7, 80
			sample.Known, sample.MemoryUsedBytes, sample.MemoryTotalBytes = false, 0, 0
			sample.RXBandwidthBPS, sample.TXBandwidthBPS, sample.Telemetry = 0, 0, nil
		}
		if _, err := store.Put(t.Context(), sample); err != nil {
			t.Fatal(err)
		}
	}
	path := "/v1/nodes/metrics/latest"
	query := "?node_id=" + ids[2].String() + "&node_id=" + ids[0].String() + "&node_id=" + ids[1].String()
	before := time.Now().UTC()
	response := doRequest(t, client, http.MethodGet, server.URL+path+query, nil, nil, readerAuth.AccessToken)
	var result struct {
		ObservedAt         time.Time             `json:"observed_at"`
		Items              []nodeMetricsResponse `json:"items"`
		NotReportedNodeIDs []uuid.UUID           `json:"not_reported_node_ids"`
	}
	decodeResponse(t, response, http.StatusOK, &result)
	response.Body.Close()
	if result.ObservedAt.Before(before) || result.ObservedAt.After(time.Now().UTC()) || result.ObservedAt.Location() != time.UTC ||
		len(result.Items) != 2 || !reflect.DeepEqual(result.NotReportedNodeIDs, []uuid.UUID{ids[2]}) {
		t.Fatalf("batch coverage/read time: %+v", result)
	}
	for index, id := range ids[:2] {
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+id.String()+"/metrics/latest", nil, nil, readerAuth.AccessToken)
		var single nodeMetricsResponse
		decodeResponse(t, response, http.StatusOK, &single)
		response.Body.Close()
		if !reflect.DeepEqual(result.Items[index], single) || !single.ObservedAt.Equal(observed) {
			t.Fatalf("batch changed original single-node evidence: batch=%+v single=%+v", result.Items[index], single)
		}
	}
	if result.Items[0].RecordKind != nodemetrics.RecordHostMetric || result.Items[0].Healthy || result.Items[0].ProbePort != 0 ||
		result.Items[0].Telemetry.NetworkSelection.Interfaces[0] != "ens17" || result.Items[1].Known || result.Items[1].RXBandwidthBPS != nil {
		t.Fatal("host-only or unknown metric semantics changed")
	}
	for _, id := range []uuid.UUID{ids[0], ids[2]} {
		response := doRequest(t, client, http.MethodGet, server.URL+path+"?node_id="+id.String(), nil, nil, readerAuth.AccessToken)
		var partition nodeMetricsBatchResponse
		decodeResponse(t, response, http.StatusOK, &partition)
		response.Body.Close()
		if partition.Items == nil || partition.NotReportedNodeIDs == nil || len(partition.Items)+len(partition.NotReportedNodeIDs) != 1 {
			t.Fatal("empty membership partitions must be arrays, not null")
		}
	}
	for _, test := range []struct {
		name, token string
		status      int
		code        string
	}{
		{"anonymous", "", http.StatusUnauthorized, "invalid_session"},
		{"no permission", viewerAuth.AccessToken, http.StatusForbidden, "permission_denied"},
		{"tenant owner", tenantAuth.AccessToken, http.StatusForbidden, "permission_denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := doRequest(t, client, http.MethodGet, server.URL+path+query, nil, nil, test.token)
			assertError(t, response, test.status, test.code, "")
			response.Body.Close()
		})
	}
	for _, invalid := range []string{"", "?node_id=", "?node_id=invalid", "?node_id=" + uuid.Nil.String(),
		"?node_id=" + strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		query + "&node_id=" + ids[0].String(), query + "&extra=1", query + "&=1", query + ";ignored=1",
		"?" + strings.Repeat("node_id="+ids[0].String()+"&", 301)} {
		t.Run("invalid "+invalid[:min(len(invalid), 75)], func(t *testing.T) {
			response := doRequest(t, client, http.MethodGet, server.URL+path+invalid, nil, nil, readerAuth.AccessToken)
			assertError(t, response, http.StatusBadRequest, "validation_error", "")
			response.Body.Close()
		})
	}
	for _, absent := range []uuid.UUID{ids[3], uuid.New()} {
		response := doRequest(t, client, http.MethodGet, server.URL+path+query+"&node_id="+absent.String(), nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusNotFound, "node_metrics_not_found", "")
		response.Body.Close()
	}
	response = doRequest(t, client, http.MethodGet, server.URL+"/v1/nodes/"+ids[2].String()+"/metrics/latest", nil, nil, readerAuth.AccessToken)
	assertError(t, response, http.StatusNotFound, "node_metrics_not_found", "")
	response.Body.Close()
	closedPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	closedReader, _ := nodemetrics.NewPostgresReader(closedPool)
	closedPool.Close()
	type singleNodeOnlyReader struct{ NodeMetricsReader }
	for _, unavailable := range []NodeMetricsReader{nil, closedReader, singleNodeOnlyReader{reader}} {
		unavailableServer := httptest.NewServer(New(pool, auth, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NodeMetricsReader: unavailable}).Handler())
		response := doRequest(t, unavailableServer.Client(), http.MethodGet, unavailableServer.URL+path+query, nil, nil, readerAuth.AccessToken)
		assertError(t, response, http.StatusServiceUnavailable, "node_metrics_unavailable", "")
		response.Body.Close()
		if unavailable == nil {
			response = doRequest(t, unavailableServer.Client(), http.MethodGet, unavailableServer.URL+"/v1/nodes/"+ids[0].String()+"/metrics/latest", nil, nil, readerAuth.AccessToken)
			assertError(t, response, http.StatusServiceUnavailable, "node_metrics_unavailable", "")
			response.Body.Close()
		}
		unavailableServer.Close()
	}
}
