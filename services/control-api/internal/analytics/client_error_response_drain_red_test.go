package analytics

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

type errorDrainHTTPClientFunc func(*http.Request) (*http.Response, error)

func (function errorDrainHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type errorDrainTrackingBody struct {
	reader         io.Reader
	readBytes      int64
	sawEOF         bool
	closed         bool
	eofBeforeClose bool
}

func (body *errorDrainTrackingBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	body.readBytes += int64(count)
	if errors.Is(err, io.EOF) {
		body.sawEOF = true
	}
	return count, err
}

func (body *errorDrainTrackingBody) Close() error {
	body.closed = true
	body.eofBeforeClose = body.sawEOF
	return nil
}

type endlessErrorDrainBody struct {
	readBytes int64
	closed    bool
}

func (body *endlessErrorDrainBody) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	body.readBytes += int64(len(buffer))
	return len(buffer), nil
}

func (body *endlessErrorDrainBody) Close() error {
	body.closed = true
	return nil
}

type failingErrorDrainBody struct {
	readBytes int64
	closed    bool
}

func (body *failingErrorDrainBody) Read(buffer []byte) (int, error) {
	count := copy(buffer, "clickhouse-storage-secret")
	body.readBytes += int64(count)
	return count, errors.New("drain failed with clickhouse-storage-secret")
}

func (body *failingErrorDrainBody) Close() error {
	body.closed = true
	return nil
}

func TestClientDrainsBoundedClickHouseErrorResponses(t *testing.T) {
	t.Run("small bodies reach EOF before close", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			status int
		}{
			{name: "rate limited", status: http.StatusTooManyRequests},
			{name: "unavailable", status: http.StatusServiceUnavailable},
		} {
			t.Run(test.name, func(t *testing.T) {
				body := &errorDrainTrackingBody{reader: strings.NewReader("retry later")}
				client := newErrorDrainTestClient(t, 64, errorDrainHTTPClientFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: test.status, Body: body}, nil
				}))

				err := client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil)
				assertStatusOnlyHTTPError(t, err, test.status)
				if !body.closed || !body.eofBeforeClose || body.readBytes != int64(len("retry later")) {
					t.Fatalf("body closed=%t eof-before-close=%t read=%d", body.closed, body.eofBeforeClose, body.readBytes)
				}
			})
		}
	})

	t.Run("HTTP 1.1 connection is reused after error", func(t *testing.T) {
		var requests atomic.Int32
		var connections atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			if requests.Add(1) == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(writer, "retry later")
				return
			}
			writer.WriteHeader(http.StatusOK)
		}))
		server.EnableHTTP2 = false
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections.Add(1)
			}
		}
		server.Start()
		t.Cleanup(server.Close)

		client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics_test", MaxResponseBytes: 64}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		assertStatusOnlyHTTPError(t,
			client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil),
			http.StatusServiceUnavailable,
		)
		if err := client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil); err != nil {
			t.Fatalf("second execute error = %v", err)
		}
		if requests.Load() != 2 || connections.Load() != 1 {
			t.Fatalf("requests=%d connections=%d, want 2 requests on 1 connection", requests.Load(), connections.Load())
		}
	})

	t.Run("endless body is bounded and closed", func(t *testing.T) {
		const (
			maxResponseBytes = int64(1 << 20)
			maxDrainBytes    = int64(64<<10) + 1
		)
		body := &endlessErrorDrainBody{}
		client := newErrorDrainTestClient(t, maxResponseBytes, errorDrainHTTPClientFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: body}, nil
		}))

		err := client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil)
		assertStatusOnlyHTTPError(t, err, http.StatusServiceUnavailable)
		if !body.closed || body.readBytes != maxDrainBytes {
			t.Fatalf("body closed=%t read=%d, want hard cap %d", body.closed, body.readBytes, maxDrainBytes)
		}
	})

	t.Run("drain read error preserves status only", func(t *testing.T) {
		body := &failingErrorDrainBody{}
		client := newErrorDrainTestClient(t, 64, errorDrainHTTPClientFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Body: body}, nil
		}))

		err := client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil)
		assertStatusOnlyHTTPError(t, err, http.StatusTooManyRequests)
		if !body.closed || body.readBytes == 0 {
			t.Fatalf("body closed=%t read=%d", body.closed, body.readBytes)
		}
	})
}

func newErrorDrainTestClient(t *testing.T, maxResponseBytes int64, httpClient HTTPClient) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", MaxResponseBytes: maxResponseBytes,
	}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func assertStatusOnlyHTTPError(t *testing.T, err error, status int) {
	t.Helper()
	httpError, ok := err.(*HTTPError)
	if !ok || httpError.StatusCode != status {
		t.Fatalf("error = %#v, want status-only HTTP %d", err, status)
	}
	if got, want := err.Error(), (&HTTPError{StatusCode: status}).Error(); got != want {
		t.Fatalf("error text = %q, want %q", got, want)
	}
}
