package analyticslog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReplicaHealthSource(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		body       string
		wantErr    error
		wantHealth bool
		wantReason []ReplicaHealthReason
	}{
		{
			name: "healthy replicated tables",
			body: replicaHealthRowJSON("cdnca", "access_events", now, 0, 0, 1, 2, 3, 2, 2) +
				replicaHealthRowJSON("cdnca", "security_events", now, 0, 0, 0, 0, 0, 2, 2),
			wantHealth: true,
		},
		{
			name: "stable degraded reasons",
			body: replicaHealthRowJSON("cdnca", "access_events", now, 1, 1, 11, 31, 21, 3, 2),
			wantReason: []ReplicaHealthReason{
				ReplicaSessionExpired,
				ReplicaReadOnly,
				ReplicaUnavailable,
				ReplicaQueueBacklog,
				ReplicaDelayExceeded,
				ReplicaLogLagExceeded,
			},
		},
		{
			name:    "database mismatch fails closed",
			body:    replicaHealthRowJSON("other", "access_events", now, 0, 0, 0, 0, 0, 1, 1),
			wantErr: ErrInvalidResponse,
		},
		{
			name: "snapshot mismatch fails closed",
			body: replicaHealthRowJSON("cdnca", "access_events", now, 0, 0, 0, 0, 0, 1, 1) +
				replicaHealthRowJSON("cdnca", "security_events", now.Add(-time.Millisecond), 0, 0, 0, 0, 0, 1, 1),
			wantErr: ErrInvalidResponse,
		},
		{
			name:    "duplicate table fails closed",
			body:    replicaHealthRowJSON("cdnca", "access_events", now, 0, 0, 0, 0, 0, 1, 1) + replicaHealthRowJSON("cdnca", "access_events", now, 0, 0, 0, 0, 0, 1, 1),
			wantErr: ErrInvalidResponse,
		},
		{name: "empty capability is explicit", wantErr: ErrCapabilityUnsupported},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &replicaHealthHTTPClient{body: test.body}
			source := newReplicaHealthTestSource(t, transport, now, 4)
			snapshot, err := source.Read(t.Context())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Read error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr != nil {
				if len(snapshot.Tables) != 0 || snapshot.Healthy || !snapshot.ObservedAt.IsZero() {
					t.Fatalf("failed read returned data: %#v", snapshot)
				}
				return
			}
			if snapshot.Database != "cdnca" || snapshot.Healthy != test.wantHealth || !snapshot.ObservedAt.Equal(now) {
				t.Fatalf("snapshot = %#v", snapshot)
			}
			if len(snapshot.Tables) == 0 || !equalReplicaReasons(snapshot.Tables[0].Reasons, test.wantReason) {
				t.Fatalf("reasons = %#v, want %#v", snapshot.Tables, test.wantReason)
			}
			if !strings.Contains(transport.query, "FROM system.replicas") ||
				transport.parameters.Get("param_database") != "cdnca" ||
				transport.parameters.Get("param_row_limit") != "5" {
				t.Fatalf("query contract = %q %#v", transport.query, transport.parameters)
			}
		})
	}
}

func TestReplicaHealthSourceCapacityAndContext(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	blocking := &replicaHealthHTTPClient{
		body:    replicaHealthRowJSON("cdnca", "access_events", now, 0, 0, 0, 0, 0, 1, 1),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	source := newReplicaHealthTestSource(t, blocking, now, 4)
	done := make(chan error, 1)
	go func() {
		_, err := source.Read(context.Background())
		done <- err
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("first read did not start")
	}
	if _, err := source.Read(t.Context()); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("second Read error = %v, want %v", err, ErrStorageUnavailable)
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatalf("first Read error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Read(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Read error = %v", err)
	}
}

func newReplicaHealthTestSource(t *testing.T, transport HTTPClient, now time.Time, maxTables int) *ReplicaHealthSource {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "cdnca", QueryTimeout: time.Second,
		MaxResponseBytes: 32 << 10, CursorKeyring: CursorKeyring{ActiveKID: "test", Keys: map[string][]byte{"test": []byte("0123456789abcdef0123456789abcdef")}},
	}, transport)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewReplicaHealthSource(client, ReplicaHealthConfig{
		QueryTimeout: time.Second, MaxConcurrent: 1, MaxTables: maxTables,
		MaxQueueSize: 10, MaxAbsoluteDelay: 30 * time.Second, MaxLogLag: 20,
		MaxSnapshotAge: time.Minute, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

type replicaHealthHTTPClient struct {
	body       string
	query      string
	parameters mapValues
	started    chan struct{}
	release    chan struct{}
}

func (client *replicaHealthHTTPClient) Do(request *http.Request) (*http.Response, error) {
	encoded, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.query = string(encoded)
	client.parameters = mapValues(request.URL.Query())
	if client.started != nil {
		close(client.started)
		client.started = nil
		<-client.release
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(client.body))}, nil
}

type mapValues map[string][]string

func (values mapValues) Get(key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return values[key][0]
}

func replicaHealthRowJSON(database, table string, observed time.Time, readOnly, expired, queue, delay, lag, total, active uint64) string {
	return `{"database":"` + database + `","table":"` + table + `","is_readonly":` + utoa(readOnly) +
		`,"is_session_expired":` + utoa(expired) + `,"queue_size":` + utoa(queue) +
		`,"absolute_delay":` + utoa(delay) + `,"log_lag":` + utoa(lag) +
		`,"total_replicas":` + utoa(total) + `,"active_replicas":` + utoa(active) +
		`,"observed_at_ms":` + itoa64(observed.UnixMilli()) + "}\n"
}

func equalReplicaReasons(got, want []ReplicaHealthReason) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func utoa(value uint64) string { return itoa64(int64(value)) }

func itoa64(value int64) string { return strconv.FormatInt(value, 10) }
