package analytics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type batchGHTTPClientFunc func(*http.Request) (*http.Response, error)

func (function batchGHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type batchGTrackingBody struct {
	reader    io.Reader
	readBytes int64
	closed    bool
	sawEOF    bool
}

func (body *batchGTrackingBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	body.readBytes += int64(count)
	body.sawEOF = body.sawEOF || errors.Is(err, io.EOF)
	return count, err
}

func (body *batchGTrackingBody) Close() error {
	body.closed = true
	return nil
}

type batchGEndlessBody struct {
	readBytes int64
	closed    bool
}

func (body *batchGEndlessBody) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	body.readBytes += int64(len(buffer))
	return len(buffer), nil
}

func (body *batchGEndlessBody) Close() error {
	body.closed = true
	return nil
}

type batchGContextErrorBody struct {
	cause  error
	closed bool
}

func (body *batchGContextErrorBody) Read(buffer []byte) (int, error) {
	return copy(buffer, "clickhouse-private-response"), fmt.Errorf("response read failed: %w", body.cause)
}

func (body *batchGContextErrorBody) Close() error {
	body.closed = true
	return nil
}

func TestClientBatchGResponseLifecycle(t *testing.T) {
	const maxResponseBytes = int64(8)

	t.Run("over-limit responses drain a bounded tail before close", func(t *testing.T) {
		calls := []struct {
			name string
			call func(*Client) error
		}{
			{name: "check", call: func(client *Client) error {
				return client.Check(context.Background())
			}},
			{name: "query", call: func(client *Client) error {
				_, err := client.Summary(context.Background(), AdminScope(), validFilter())
				return err
			}},
			{name: "write", call: func(client *Client) error {
				return client.WriteAccessEvents(context.Background(), "batch-g-over-limit", []AccessEvent{validAccessEvent("batch-g-over-limit")})
			}},
		}
		for _, call := range calls {
			t.Run(call.name, func(t *testing.T) {
				body := &batchGTrackingBody{reader: strings.NewReader(strings.Repeat("x", int(maxResponseBytes)+2))}
				client := newBatchGClient(t, maxResponseBytes, http.StatusOK, body)
				err := call.call(client)
				if !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("error = %v, want %v", err, ErrResponseTooLarge)
				}
				if !body.closed || !body.sawEOF || body.readBytes != maxResponseBytes+2 {
					t.Fatalf("closed=%t EOF=%t read=%d, want true/true/%d", body.closed, body.sawEOF, body.readBytes, maxResponseBytes+2)
				}
			})
		}

		body := &batchGEndlessBody{}
		client := newBatchGClient(t, maxResponseBytes, http.StatusOK, body)
		err := client.execute(context.Background(), time.Second, []byte("SELECT 1"), nil, false, nil)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("endless response error = %v, want %v", err, ErrResponseTooLarge)
		}
		const wantReadBytes = (maxResponseBytes + 1) * 2
		if !body.closed || body.readBytes != wantReadBytes {
			t.Fatalf("endless body closed=%t read=%d, want true/%d", body.closed, body.readBytes, wantReadBytes)
		}
	})

	t.Run("response read context causes stay canonical and bodies close", func(t *testing.T) {
		calls := []struct {
			name   string
			status int
			cause  error
			call   func(*Client) error
		}{
			{name: "check cancellation", status: http.StatusOK, cause: context.Canceled, call: func(client *Client) error {
				return client.Check(context.Background())
			}},
			{name: "query deadline", status: http.StatusServiceUnavailable, cause: context.DeadlineExceeded, call: func(client *Client) error {
				_, err := client.Summary(context.Background(), AdminScope(), validFilter())
				return err
			}},
			{name: "write cancellation", status: http.StatusServiceUnavailable, cause: context.Canceled, call: func(client *Client) error {
				return client.WriteAccessEvents(context.Background(), "batch-g-cancel", []AccessEvent{validAccessEvent("batch-g-cancel")})
			}},
		}
		for _, call := range calls {
			t.Run(call.name, func(t *testing.T) {
				body := &batchGContextErrorBody{cause: call.cause}
				client := newBatchGClient(t, maxResponseBytes, call.status, body)
				err := call.call(client)
				if !errors.Is(err, call.cause) {
					t.Fatalf("error = %v, want errors.Is(_, %v)", err, call.cause)
				}
				var httpError *HTTPError
				if errors.As(err, &httpError) || errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("context cause replaced by response error: %v", err)
				}
				if strings.Contains(err.Error(), "private-response") {
					t.Fatalf("error leaked response text: %v", err)
				}
				if !body.closed {
					t.Fatal("response body was not closed")
				}
			})
		}
	})
}

func newBatchGClient(t *testing.T, maxResponseBytes int64, status int, body io.ReadCloser) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", MaxResponseBytes: maxResponseBytes,
	}, batchGHTTPClientFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: body}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

var _ io.ReadCloser = (*batchGTrackingBody)(nil)
var _ io.ReadCloser = (*batchGEndlessBody)(nil)
var _ io.ReadCloser = (*batchGContextErrorBody)(nil)
