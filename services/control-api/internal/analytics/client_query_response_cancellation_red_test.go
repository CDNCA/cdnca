package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type queryCancellationHTTPClient struct {
	bodyReady chan *queryCancellationBody
}

func (client *queryCancellationHTTPClient) Do(request *http.Request) (*http.Response, error) {
	body := &queryCancellationBody{ctx: request.Context(), readStarted: make(chan struct{})}
	client.bodyReady <- body
	return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: body}, nil
}

type queryCancellationBody struct {
	ctx         context.Context
	readStarted chan struct{}
	startOnce   sync.Once
	reads       atomic.Int32
	closes      atomic.Int32
}

func (body *queryCancellationBody) Read(buffer []byte) (int, error) {
	body.reads.Add(1)
	body.startOnce.Do(func() { close(body.readStarted) })
	<-body.ctx.Done()
	return copy(buffer, "clickhouse-private-error-body"), body.ctx.Err()
}

func (body *queryCancellationBody) Close() error {
	body.closes.Add(1)
	return nil
}

type queryCancellationOutcome struct {
	zero bool
	err  error
}

type completedErrorHTTPClient struct {
	status int
	body   *completedErrorBody
}

func (client *completedErrorHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: client.status, Body: client.body}, nil
}

type completedErrorBody struct {
	reader strings.Reader
	cancel context.CancelFunc
	eof    atomic.Bool
	closes atomic.Int32
}

func (body *completedErrorBody) Read(buffer []byte) (int, error) {
	count, err := body.reader.Read(buffer)
	if errors.Is(err, io.EOF) {
		body.eof.Store(true)
		body.cancel()
	}
	return count, err
}

func (body *completedErrorBody) Close() error {
	body.closes.Add(1)
	return nil
}

func TestClientQueryErrorResponseHonorsCancellation(t *testing.T) {
	filter := validFilter()
	queryCases := []struct {
		name string
		call func(*Client, context.Context) (bool, error)
	}{
		{name: "summary", call: func(client *Client, ctx context.Context) (bool, error) {
			result, err := client.Summary(ctx, AdminScope(), filter)
			return result == (Summary{}), err
		}},
		{name: "trend", call: func(client *Client, ctx context.Context) (bool, error) {
			result, err := client.Trend(ctx, AdminScope(), filter)
			return result == nil, err
		}},
		{name: "top", call: func(client *Client, ctx context.Context) (bool, error) {
			result, err := client.Top(ctx, AdminScope(), filter, TopBySite, 2)
			return result == nil, err
		}},
		{name: "rank without cursor", call: func(client *Client, ctx context.Context) (bool, error) {
			result, err := client.Rank(ctx, AdminScope(), filter, RankByURL, 2, "")
			return zeroRankPage(result), err
		}},
		{name: "rank with cursor", call: func(client *Client, ctx context.Context) (bool, error) {
			cursor, err := encodeRankCursor(rankCursor{
				Version: 1, Query: rankFingerprint(AdminScope(), filter, RankByURL),
				SnapshotMilli: time.Now().UTC().Add(-time.Minute).UnixMilli(),
				ResponseBytes: 100, RequestCount: 10, Key: "/cursor",
			})
			if err != nil {
				return false, err
			}
			result, err := client.Rank(ctx, AdminScope(), filter, RankByURL, 2, cursor)
			return zeroRankPage(result), err
		}},
	}
	modes := []struct {
		name         string
		queryTimeout time.Duration
		want         error
		cancel       bool
	}{
		{name: "caller cancellation", queryTimeout: 2 * time.Second, want: context.Canceled, cancel: true},
		{name: "query timeout", queryTimeout: 25 * time.Millisecond, want: context.DeadlineExceeded},
	}

	for _, queryCase := range queryCases {
		for _, mode := range modes {
			t.Run(queryCase.name+"/"+mode.name, func(t *testing.T) {
				httpClient := &queryCancellationHTTPClient{bodyReady: make(chan *queryCancellationBody, 1)}
				client := mustClient(t, Config{
					Endpoint: "https://clickhouse.example.test", Database: "analytics_test", QueryTimeout: mode.queryTimeout,
				}, httpClient)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				outcomes := make(chan queryCancellationOutcome, 1)
				go func() {
					zero, err := queryCase.call(client, ctx)
					outcomes <- queryCancellationOutcome{zero: zero, err: err}
				}()

				body := awaitQueryCancellationBody(t, httpClient.bodyReady)
				awaitQueryCancellationRead(t, body.readStarted)
				if mode.cancel {
					cancel()
				}
				result := awaitQueryCancellationOutcome(t, outcomes)
				if !result.zero {
					t.Fatal("query returned a non-zero result")
				}
				if !errors.Is(result.err, mode.want) || result.err != mode.want {
					t.Fatalf("error = %#v, want exact %v", result.err, mode.want)
				}
				var httpError *HTTPError
				if errors.As(result.err, &httpError) {
					t.Fatalf("error exposed HTTP status: %#v", result.err)
				}
				if strings.Contains(result.err.Error(), "clickhouse-private-error-body") {
					t.Fatalf("error leaked private response text: %v", result.err)
				}
				if body.reads.Load() != 1 || body.closes.Load() != 1 {
					t.Fatalf("body reads=%d closes=%d, want 1/1", body.reads.Load(), body.closes.Load())
				}
			})
		}
	}
}

func TestClientCompletedErrorResponsePreservesKnownHTTPStatus(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		body := &completedErrorBody{reader: *strings.NewReader("known query rejection"), cancel: cancel}
		client := mustClient(t, Config{
			Endpoint: "https://clickhouse.example.test", Database: "analytics_test", QueryTimeout: time.Second,
		}, &completedErrorHTTPClient{status: http.StatusServiceUnavailable, body: body})

		result, err := client.Summary(ctx, AdminScope(), validFilter())
		if result != (Summary{}) {
			t.Fatalf("result = %#v, want zero summary", result)
		}
		assertKnownHTTPStatusAfterEOF(t, ctx, body, err, http.StatusServiceUnavailable)
	})

	t.Run("write", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		body := &completedErrorBody{reader: *strings.NewReader("known write rejection"), cancel: cancel}
		client := mustClient(t, Config{
			Endpoint: "https://clickhouse.example.test", Database: "analytics_test", WriteTimeout: time.Second,
		}, &completedErrorHTTPClient{status: http.StatusBadRequest, body: body})

		err := client.WriteAccessEvents(ctx, "known-write-rejection", []AccessEvent{validAccessEvent("known-write-rejection")})
		if errors.Is(err, ErrIngestWriteOutcomeUnknown) {
			t.Fatalf("completed HTTP rejection became unknown write outcome: %v", err)
		}
		assertKnownHTTPStatusAfterEOF(t, ctx, body, err, http.StatusBadRequest)
	})
}

func assertKnownHTTPStatusAfterEOF(
	t *testing.T,
	ctx context.Context,
	body *completedErrorBody,
	err error,
	wantStatus int,
) {
	t.Helper()
	if !body.eof.Load() || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("body EOF=%t caller error=%v, want completed body then cancellation", body.eof.Load(), ctx.Err())
	}
	var httpError *HTTPError
	if !errors.As(err, &httpError) || httpError.StatusCode != wantStatus {
		t.Fatalf("error = %#v, want status-only HTTP %d", err, wantStatus)
	}
	if errors.Is(err, context.Canceled) || body.closes.Load() != 1 {
		t.Fatalf("error=%v closes=%d, want known HTTP status and one close", err, body.closes.Load())
	}
}

func zeroRankPage(page RankPage) bool {
	return page.Items == nil && page.NextCursor == "" && page.SnapshotAt.IsZero()
}

func awaitQueryCancellationBody(t *testing.T, ready <-chan *queryCancellationBody) *queryCancellationBody {
	t.Helper()
	select {
	case body := <-ready:
		return body
	case <-time.After(time.Second):
		t.Fatal("HTTP client did not receive the query")
		return nil
	}
}

func awaitQueryCancellationRead(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("error response body was not read")
	}
}

func awaitQueryCancellationOutcome(t *testing.T, outcomes <-chan queryCancellationOutcome) queryCancellationOutcome {
	t.Helper()
	select {
	case result := <-outcomes:
		return result
	case <-time.After(time.Second):
		t.Fatal("query did not return after cancellation")
		return queryCancellationOutcome{}
	}
}

var _ io.ReadCloser = (*queryCancellationBody)(nil)
var _ io.ReadCloser = (*completedErrorBody)(nil)
