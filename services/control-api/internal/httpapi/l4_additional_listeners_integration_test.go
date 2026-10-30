package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

func TestL4AdditionalListenersHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenant := insertL4Tenant(t, pool, "Multi listener tenant", "multi-owner", passwordHash, []string{"streams.read", "streams.manage"})
	other := insertL4Tenant(t, pool, "Other listener tenant", "multi-other", passwordHash, []string{"streams.read", "streams.manage"})
	insertL4ScopeUser(t, pool, tenant.scopeID, "multi-viewer", "Viewer", passwordHash, []string{"streams.read"})
	tokens, err := identity.NewTokenManager("l4-additional-listener-integration-secret-32-bytes", 5*time.Minute)
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
	auth, _ := loginOK(t, client, server.URL, "multi-owner")
	otherAuth, _ := loginOK(t, client, server.URL, "multi-other")
	viewerAuth, _ := loginOK(t, client, server.URL, "multi-viewer")
	raw, err := json.Marshal(validStreamFields(tenant, "Multiple listeners", "tcp", 19100, "192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	body["proxy_protocol_v1"] = false
	extraID := "11111111-1111-4111-8111-111111111111"
	secondID := "22222222-2222-4222-8222-222222222222"
	body["additional_listeners"] = []any{
		map[string]any{"id": secondID, "protocol": "tcp", "address": "*", "port": 19102},
		map[string]any{"id": extraID, "protocol": "udp", "address": "*", "port": 19101},
	}
	response := l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", body, auth.AccessToken, "multi-create", "")
	var created map[string]any
	decodeResponse(t, response, http.StatusCreated, &created)
	response.Body.Close()
	if listeners, ok := created["additional_listeners"].([]any); !ok || len(listeners) != 2 || listeners[0].(map[string]any)["id"] != extraID {
		t.Fatalf("additional listener missing from response: %+v", created)
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_forward_listeners WHERE stream_id=$1 AND reserved`, created["id"]).Scan(&count); err != nil || count != 3 {
		t.Fatalf("durable listener count=%d err=%v", count, err)
	}
	streamID := uuid.MustParse(created["id"].(string))
	current := getL4Forward(t, client, server.URL, streamID, auth.AccessToken)
	if len(current.AdditionalListeners) != 2 || !reflect.DeepEqual(current.AdditionalListeners, current.PublishIntent.RuntimeSpec.AdditionalListeners) {
		t.Fatalf("stored/runtime listeners differ: %+v", current)
	}
	originalIntent := current.PublishIntent
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", body, auth.AccessToken, "multi-create", "")
	var replay l4forward.Forward
	decodeResponse(t, response, http.StatusCreated, &replay)
	response.Body.Close()
	if replay.ID != current.ID || replay.PublishIntent.ID != current.PublishIntent.ID || !reflect.DeepEqual(replay.AdditionalListeners, current.AdditionalListeners) {
		t.Fatal("create retry changed listener identities or intent")
	}
	for _, test := range []struct {
		query, token string
		total        int64
	}{
		{"protocol=udp&listen_port=19101", auth.AccessToken, 1},
		{"protocol=tcp&listen_port=19101", auth.AccessToken, 0},
		{"listen_port=19102&page=2&limit=1", auth.AccessToken, 1},
		{"listen_port=19101", otherAuth.AccessToken, 0},
		{"listen_port=19101", viewerAuth.AccessToken, 0},
	} {
		result := listL4Forwards(t, client, server.URL+"/v1/streams?"+test.query, test.token)
		if result.Total != test.total {
			t.Fatalf("%s total=%d want=%d", test.query, result.Total, test.total)
		}
	}
	response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", body, viewerAuth.AccessToken, "viewer-denied", "")
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer write=%d", response.StatusCode)
	}

	t.Run("strict additional listener input", func(t *testing.T) {
		for index, listeners := range []any{
			nil, map[string]any{}, []any{map[string]any{"protocol": "tcp", "address": "*", "port": 19103}},
			[]any{map[string]any{"id": uuid.Nil, "protocol": "tcp", "address": "*", "port": 19103}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "127.0.0.1", "port": 19103}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "TCP", "address": "*", "port": 19103}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "*", "port": 65536}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "*", "port": 0}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "*", "port": 19103, "unknown": true}},
			[]any{map[string]any{"id": extraID, "protocol": "tcp", "address": "*", "port": 19103}, map[string]any{"id": extraID, "protocol": "udp", "address": "*", "port": 19104}},
			[]any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "*", "port": 19100}},
			[]any{map[string]any{"id": streamID, "protocol": "tcp", "address": "*", "port": 19103}},
		} {
			invalid := cloneAdditionalBody(t, body)
			invalid["additional_listeners"], invalid["expected_revision"] = listeners, current.Revision
			response := l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+streamID.String(), invalid, auth.AccessToken, fmt.Sprintf("multi-invalid-%d", index), fmt.Sprintf(`"%d"`, current.Revision))
			response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("invalid %d status=%d", index, response.StatusCode)
			}
		}
	})

	fields := validStreamFields(tenant, "Multiple listeners updated", "tcp", 19100, "192.0.2.10")
	fields.ProxyProtocolV1 = false
	current = updateL4Forward(t, client, server.URL, streamID, auth.AccessToken, "multi-omit", updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, current.Revision)
	if len(current.AdditionalListeners) != 2 {
		t.Fatal("omitted update deleted listeners")
	}
	fields.ProxyProtocolV1 = true
	response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+streamID.String(), updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, auth.AccessToken, "multi-udp-proxy", fmt.Sprintf(`"%d"`, current.Revision))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("existing UDP with PROXY accepted: %d", response.StatusCode)
	}
	fields.ProxyProtocolV1 = false

	t.Run("database rejects fact drift and identity mutation", func(t *testing.T) {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`UPDATE l4_forward_listeners SET port=19200 WHERE id=$1`, []any{streamID}},
			{`DELETE FROM l4_forward_listeners WHERE id=$1`, []any{extraID}},
			{`UPDATE l4_forward_listeners SET stream_id=$1 WHERE id=$2`, []any{uuid.New(), extraID}},
			{`UPDATE l4_forward_listeners SET port=19200 WHERE id=$1`, []any{extraID}},
			{`UPDATE l4_forwards SET revision=revision+1 WHERE id=$1`, []any{streamID}},
		} {
			if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err == nil {
				t.Fatalf("unsafe write accepted: %s", statement.query)
			}
		}
	})

	// Promoting the UDP extra releases its reservation before the primary slot claims it.
	remaining := []l4forward.AdditionalListener{current.AdditionalListeners[1]}
	fields.Protocol, fields.ListenPort, fields.AdditionalListeners = "udp", 19101, &remaining
	current = updateL4Forward(t, client, server.URL, streamID, auth.AccessToken, "multi-promote", updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, current.Revision)
	if current.ListenPort != 19101 || len(current.AdditionalListeners) != 1 || current.AdditionalListeners[0].ID.String() != secondID {
		t.Fatalf("promotion lost identity: %+v", current)
	}

	// Explicit [] and omission must have different digests, and clearing must release the socket.
	empty := []l4forward.AdditionalListener{}
	fields.AdditionalListeners = &empty
	clearRequest := updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}
	clearRevision := current.Revision
	current = updateL4Forward(t, client, server.URL, streamID, auth.AccessToken, "multi-clear", clearRequest, clearRevision)
	if len(current.AdditionalListeners) != 0 || len(current.PublishIntent.RuntimeSpec.AdditionalListeners) != 0 {
		t.Fatal("explicit empty did not clear")
	}
	clearRequest.Fields.AdditionalListeners = nil
	response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+streamID.String(), clearRequest, auth.AccessToken, "multi-clear", fmt.Sprintf(`"%d"`, clearRevision))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("omitted/empty digest not distinguished: %d", response.StatusCode)
	}

	reused := createL4Forward(t, client, server.URL, auth.AccessToken, "multi-reused-port", createStreamRequest{Fields: validStreamFields(tenant, "Released socket", "tcp", 19102, "192.0.2.10")})
	conflict := []l4forward.AdditionalListener{{ID: uuid.New(), Protocol: "tcp", Address: "*", Port: 19102}}
	fields.AdditionalListeners = &conflict
	response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+streamID.String(), updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, auth.AccessToken, "multi-conflict", fmt.Sprintf(`"%d"`, current.Revision))
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("main/extra conflict=%d", response.StatusCode)
	}
	if got := getL4Forward(t, client, server.URL, streamID, auth.AccessToken); got.Revision != current.Revision || len(got.AdditionalListeners) != 0 {
		t.Fatal("conflict did not roll back")
	}
	conflict[0].ID, conflict[0].Port = reused.ID, 19105
	response = l4Request(t, client, http.MethodPatch, server.URL+"/v1/streams/"+streamID.String(), updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, auth.AccessToken, "multi-id-conflict", fmt.Sprintf(`"%d"`, current.Revision))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("other stream ID accepted: %d", response.StatusCode)
	}

	// Deletion preserves the immutable extra snapshot while releasing every socket.
	conflict[0].ID, conflict[0].Port = uuid.New(), 19106
	current = updateL4Forward(t, client, server.URL, streamID, auth.AccessToken, "multi-before-delete", updateStreamRequest{ExpectedRevision: current.Revision, Fields: fields}, current.Revision)
	deleteURL := server.URL + "/v1/streams/" + streamID.String()
	for attempt := 0; attempt < 2; attempt++ {
		response = l4Request(t, client, http.MethodDelete, deleteURL, nil, auth.AccessToken, "multi-delete", fmt.Sprintf(`"%d"`, current.Revision))
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete retry %d=%d", attempt, response.StatusCode)
		}
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_forward_listeners WHERE stream_id=$1 AND reserved`, streamID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("delete reservations=%d %v", count, err)
	}
	var runtime []byte
	if err := pool.QueryRow(t.Context(), `SELECT runtime_spec FROM l4_publish_intents WHERE id=$1`, originalIntent.ID).Scan(&runtime); err != nil {
		t.Fatal(err)
	}
	var historical l4forward.RuntimeSpec
	if err := json.Unmarshal(runtime, &historical); err != nil || len(historical.AdditionalListeners) != 2 {
		t.Fatalf("historical runtime changed: %s %v", runtime, err)
	}
	createL4Forward(t, client, server.URL, auth.AccessToken, "multi-after-delete", createStreamRequest{Fields: validStreamFields(tenant, "Deleted socket", "tcp", 19106, "192.0.2.10")})

	t.Run("concurrent main and extra port claims", func(t *testing.T) {
		first := additionalBody(t, validStreamFields(tenant, "Race primary", "tcp", 19300, "192.0.2.10"))
		second := additionalBody(t, validStreamFields(other, "Race extra", "tcp", 19301, "192.0.2.10"))
		second["additional_listeners"] = []any{map[string]any{"id": uuid.NewString(), "protocol": "tcp", "address": "*", "port": 19300}}
		statuses := make(chan int, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for index, candidate := range []struct {
			body  map[string]any
			token string
		}{{first, auth.AccessToken}, {second, otherAuth.AccessToken}} {
			encoded, err := json.Marshal(candidate.body)
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func(index int, encoded []byte, token string) {
				defer wg.Done()
				<-start
				request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/streams", bytes.NewReader(encoded))
				if err != nil {
					statuses <- 0
					return
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("Idempotency-Key", fmt.Sprintf("multi-race-%d", index))
				response, err := client.Do(request)
				if err != nil {
					statuses <- 0
					return
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				statuses <- response.StatusCode
			}(index, encoded, candidate.token)
		}
		close(start)
		wg.Wait()
		close(statuses)
		counts := map[int]int{}
		for status := range statuses {
			counts[status]++
		}
		if counts[http.StatusCreated] != 1 || counts[http.StatusConflict] != 1 {
			t.Fatalf("race outcomes=%v", counts)
		}
	})
	t.Run("maximum listener count and website conflict", func(t *testing.T) {
		maxFields := validStreamFields(tenant, "Maximum listeners", "tcp", 19999, "192.0.2.10")
		// 64 个监听各占一个四层端口配额，超过夹具套餐的 10 个；这里只测数量上限，用不限端口的套餐。
		maxFields.PackageSubscriptionID = new(insertL4PackageSubscriptionWithStreamPorts(t, pool, tenant.scopeID, tenant.userID, -1))
		listeners := make([]l4forward.AdditionalListener, 64)
		for index := range listeners {
			listeners[index] = l4forward.AdditionalListener{ID: uuid.New(), Protocol: "tcp", Address: "*", Port: uint16(20000 + index)}
		}
		maxFields.AdditionalListeners = &listeners
		response := l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: maxFields}, auth.AccessToken, "multi-too-many", "")
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("64 extras accepted: %d", response.StatusCode)
		}
		listeners = listeners[:63]
		maximum := createL4Forward(t, client, server.URL, auth.AccessToken, "multi-maximum", createStreamRequest{Fields: maxFields})
		if len(maximum.AdditionalListeners) != 63 {
			t.Fatal("maximum listener set not persisted")
		}
		maxFields.Name, maxFields.ListenPort = "Website conflict", 20100
		listeners = []l4forward.AdditionalListener{{ID: uuid.New(), Protocol: "tcp", Address: "*", Port: 18080}}
		response = l4Request(t, client, http.MethodPost, server.URL+"/v1/streams", createStreamRequest{Fields: maxFields}, auth.AccessToken, "multi-site-conflict", "")
		response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("website port accepted: %d", response.StatusCode)
		}
	})
	t.Run("rollback retains new listener facts and history", func(t *testing.T) {
		down, err := controlmigrations.FS.ReadFile("248_l4_additional_listeners.down.sql")
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), string(down)); err == nil {
			t.Fatal("destructive listener rollback accepted")
		}
	})
}

func cloneAdditionalBody(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func additionalBody(t *testing.T, fields l4forward.Fields) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	return body
}
