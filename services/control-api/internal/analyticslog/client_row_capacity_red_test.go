package analyticslog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var rowCapacityUnmarshalCalls atomic.Int64

type rowCapacityCountingRow struct{}

func (*rowCapacityCountingRow) UnmarshalJSON([]byte) error {
	rowCapacityUnmarshalCalls.Add(1)
	return nil
}

func TestQueryRowsRowCapacityRejectsOverflowBeforeGrowth(t *testing.T) {
	const maximumRows = 3
	rowCapacityUnmarshalCalls.Store(0)
	client, requests := rowCapacityTestClient(t, []byte(strings.Repeat("{}\n", maximumRows+100)))

	rows, err := queryRows[rowCapacityCountingRow](client, context.Background(), "SELECT overflow", url.Values{}, maximumRows)
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want ErrInvalidResponse", err)
	}
	if rows != nil {
		t.Fatalf("rows=%#v, want nil without an oversized backing result", rows)
	}
	if got := rowCapacityUnmarshalCalls.Load(); got != maximumRows+1 {
		t.Fatalf("UnmarshalJSON calls=%d, want %d", got, maximumRows+1)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests=%d, want 1", got)
	}
}

func TestQueryRowsRowCapacityAcceptsExactMaximum(t *testing.T) {
	const maximumRows = 3
	rowCapacityUnmarshalCalls.Store(0)
	client, _ := rowCapacityTestClient(t, []byte(strings.Repeat("{}\n", maximumRows)))

	rows, err := queryRows[rowCapacityCountingRow](client, context.Background(), "SELECT exact", url.Values{}, maximumRows)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != maximumRows {
		t.Fatalf("rows=%d, want %d", len(rows), maximumRows)
	}
	if got := rowCapacityUnmarshalCalls.Load(); got != maximumRows {
		t.Fatalf("UnmarshalJSON calls=%d, want %d", got, maximumRows)
	}
}

func TestQueryRowsRowCapacityRejectsInvalidMaximumBeforeRequest(t *testing.T) {
	for _, test := range []struct {
		name        string
		maximumRows int
	}{
		{name: "zero", maximumRows: 0},
		{name: "negative", maximumRows: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			rowCapacityUnmarshalCalls.Store(0)
			client, requests := rowCapacityTestClient(t, []byte("{}\n"))

			rows, err := queryRows[rowCapacityCountingRow](client, context.Background(), "SELECT invalid", url.Values{}, test.maximumRows)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("maximumRows=%d error=%v, want ErrInvalidResponse", test.maximumRows, err)
			}
			if rows != nil {
				t.Fatalf("maximumRows=%d rows=%#v, want nil", test.maximumRows, rows)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("maximumRows=%d HTTP requests=%d, want 0", test.maximumRows, got)
			}
			if got := rowCapacityUnmarshalCalls.Load(); got != 0 {
				t.Fatalf("maximumRows=%d UnmarshalJSON calls=%d, want 0", test.maximumRows, got)
			}
		})
	}
}

func TestQueryRowsRowCapacityRejectsMalformedUTF8BeforeUnmarshal(t *testing.T) {
	rowCapacityUnmarshalCalls.Store(0)
	body := append([]byte("{}\n"), 0xff, '\n')
	client, _ := rowCapacityTestClient(t, body)

	rows, err := queryRows[rowCapacityCountingRow](client, context.Background(), "SELECT invalid_utf8", url.Values{}, 3)
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want ErrInvalidResponse", err)
	}
	if rows != nil {
		t.Fatalf("rows=%#v, want nil", rows)
	}
	if got := rowCapacityUnmarshalCalls.Load(); got != 0 {
		t.Fatalf("UnmarshalJSON calls=%d, want 0 before raw UTF-8 rejection", got)
	}
}

func rowCapacityTestClient(t *testing.T, body []byte) (*Client, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return newUnitClient(t, server, time.Second), &requests
}
