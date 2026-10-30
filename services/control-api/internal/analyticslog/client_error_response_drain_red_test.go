package analyticslog

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDrainsBoundedClickHouseErrorResponses(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}

	t.Run("small_error_bodies_reach_eof_before_close", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			status int
			query  func(*Client) error
		}{
			{
				name: "access_429", status: http.StatusTooManyRequests,
				query: func(client *Client) error {
					_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
					return err
				},
			},
			{
				name: "block_503", status: http.StatusServiceUnavailable,
				query: func(client *Client) error {
					_, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
					return err
				},
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				body := &errorDrainEOFBody{payload: []byte("private ClickHouse error")}
				client := newErrorDrainClient(t, 1024, errorDrainHTTPClient{response: &http.Response{
					StatusCode: test.status,
					Body:       body,
				}})

				if err := test.query(client); err != ErrStorageUnavailable {
					t.Fatalf("error=%v, want exactly ErrStorageUnavailable", err)
				}
				if !body.sawEOF || body.closedBeforeEOF || !body.closed {
					t.Fatalf("body state: sawEOF=%t closedBeforeEOF=%t closed=%t", body.sawEOF, body.closedBeforeEOF, body.closed)
				}
			})
		}
	})

	t.Run("error_then_success_reuses_http1_connection", func(t *testing.T) {
		var requests atomic.Int64
		var connections atomic.Int64
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.ProtoMajor != 1 {
				t.Errorf("protocol=%q, want HTTP/1.1", request.Proto)
			}
			if requests.Add(1) == 1 {
				writer.Header().Set("Content-Length", "32768")
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(writer, strings.Repeat("x", 32768))
				return
			}
			writer.WriteHeader(http.StatusOK)
		}))
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
		server.Start()
		defer server.Close()

		client := newUnitClient(t, server, time.Second)
		if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); err != ErrStorageUnavailable {
			t.Fatalf("first error=%v, want exactly ErrStorageUnavailable", err)
		}
		if page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); err != nil || len(page.Items) != 0 {
			t.Fatalf("second page=%#v error=%v", page, err)
		}
		if got := connections.Load(); got != 1 {
			t.Fatalf("HTTP/1.1 connections=%d, want one reused connection", got)
		}
	})

	t.Run("endless_body_is_bounded_and_closed", func(t *testing.T) {
		for _, maximum := range []int64{37, 1 << 20} {
			body := &errorDrainEndlessBody{}
			client := newErrorDrainClient(t, maximum, errorDrainHTTPClient{response: &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       body,
			}})

			if err := client.execute(context.Background(), "SELECT bounded", nil, nil); err != ErrStorageUnavailable {
				t.Fatalf("maximum=%d error=%v, want exactly ErrStorageUnavailable", maximum, err)
			}
			want := min(maximum, int64(64<<10)) + 1
			if body.read != want || !body.closed {
				t.Fatalf("maximum=%d read=%d closed=%t, want read=%d closed=true", maximum, body.read, body.closed, want)
			}
		}
	})

	t.Run("drain_failure_does_not_leak", func(t *testing.T) {
		privateErr := errors.New("private clickhouse read failure")
		body := &errorDrainFailureBody{err: privateErr}
		client := newErrorDrainClient(t, 1024, errorDrainHTTPClient{response: &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       body,
		}})

		err := client.execute(context.Background(), "SELECT failure", nil, nil)
		if err != ErrStorageUnavailable {
			t.Fatalf("error=%v, want exactly ErrStorageUnavailable", err)
		}
		if body.reads != 1 || !body.closed {
			t.Fatalf("reads=%d closed=%t, want one read and close", body.reads, body.closed)
		}
		if errors.Is(err, privateErr) || strings.Contains(err.Error(), privateErr.Error()) {
			t.Fatalf("private drain error leaked: %v", err)
		}
	})
}

type errorDrainHTTPClient struct {
	response *http.Response
}

func (client errorDrainHTTPClient) Do(*http.Request) (*http.Response, error) {
	return client.response, nil
}

type errorDrainEOFBody struct {
	payload         []byte
	offset          int
	sawEOF          bool
	closed          bool
	closedBeforeEOF bool
}

func (body *errorDrainEOFBody) Read(buffer []byte) (int, error) {
	if body.offset == len(body.payload) {
		body.sawEOF = true
		return 0, io.EOF
	}
	read := copy(buffer, body.payload[body.offset:])
	body.offset += read
	return read, nil
}

func (body *errorDrainEOFBody) Close() error {
	body.closed = true
	body.closedBeforeEOF = !body.sawEOF
	return nil
}

type errorDrainEndlessBody struct {
	read   int64
	closed bool
}

func (body *errorDrainEndlessBody) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	body.read += int64(len(buffer))
	return len(buffer), nil
}

func (body *errorDrainEndlessBody) Close() error {
	body.closed = true
	return nil
}

type errorDrainFailureBody struct {
	err    error
	reads  int
	closed bool
}

func (body *errorDrainFailureBody) Read([]byte) (int, error) {
	body.reads++
	return 0, body.err
}

func (body *errorDrainFailureBody) Close() error {
	body.closed = true
	return nil
}

func newErrorDrainClient(t *testing.T, maximum int64, httpClient HTTPClient) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "task_analyticslog_error_drain",
		QueryTimeout: time.Second, MaxResponseBytes: maximum, CursorKeyring: testLogCursorKeyring(),
	}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
