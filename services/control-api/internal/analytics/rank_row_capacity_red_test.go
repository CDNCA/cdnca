package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestRankRowCapacity(t *testing.T) {
	t.Run("non-positive maximum rejects before HTTP", func(t *testing.T) {
		for _, maximumRows := range []int{0, -1} {
			var requests atomic.Int32
			client := newRankCapacityTestClient(t, nil, &requests, nil)
			rows, err := queryRankRows(client, context.Background(), rankByURLSQL, nil, maximumRows)
			if !errors.Is(err, ErrInvalidResponse) || rows != nil {
				t.Fatalf("queryRankRows(maximumRows=%d) = %#v, %v; want nil, ErrInvalidResponse", maximumRows, rows, err)
			}
			if requests.Load() != 0 {
				t.Fatalf("queryRankRows(maximumRows=%d) HTTP requests = %d, want 0", maximumRows, requests.Load())
			}
		}
	})

	t.Run("exact maximum is accepted", func(t *testing.T) {
		want := []RankItem{
			{Key: "/a", RequestCount: 2, ResponseBytes: 200},
			{Key: "/b", RequestCount: 1, ResponseBytes: 100},
		}
		var requests atomic.Int32
		client := newRankCapacityTestClient(t, rankRowsJSON(t, want), &requests, nil)
		rows, err := queryRankRows(client, context.Background(), rankByURLSQL, nil, len(want))
		if err != nil || len(rows) != len(want) || rows[0] != want[0] || rows[1] != want[1] {
			t.Fatalf("queryRankRows() = %#v, %v; want %#v, nil", rows, err, want)
		}
		if requests.Load() != 1 {
			t.Fatalf("queryRankRows() HTTP requests = %d, want 1", requests.Load())
		}
	})

	t.Run("first excess row fails closed before append", func(t *testing.T) {
		encoded := rankRowsJSON(t, []RankItem{
			{Key: "/a", RequestCount: 3, ResponseBytes: 300},
			{Key: "/b", RequestCount: 2, ResponseBytes: 200},
			{Key: "/c", RequestCount: 1, ResponseBytes: 100},
		})
		var requests atomic.Int32
		client := newRankCapacityTestClient(t, encoded, &requests, nil)
		rows, err := queryRankRows(client, context.Background(), rankByURLSQL, nil, 2)
		if !errors.Is(err, ErrInvalidResponse) || rows != nil {
			t.Fatalf("queryRankRows() = %#v, %v; want nil, ErrInvalidResponse", rows, err)
		}
		if requests.Load() != 1 {
			t.Fatalf("queryRankRows() HTTP requests = %d, want 1", requests.Load())
		}
	})

	t.Run("Rank permits only the limit plus one probe", func(t *testing.T) {
		encoded := rankRowsJSON(t, []RankItem{
			{Key: "/a", RequestCount: 3, ResponseBytes: 300},
			{Key: "/b", RequestCount: 2, ResponseBytes: 200},
			{Key: "/c", RequestCount: 1, ResponseBytes: 100},
		})
		var parameters url.Values
		client := newRankCapacityTestClient(t, encoded, nil, &parameters)
		page, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByURL, 2, "")
		if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
			t.Fatalf("Rank() = %#v, %v; want two items and a cursor", page, err)
		}
		if got := parameters.Get("param_row_limit"); got != strconv.Itoa(3) {
			t.Fatalf("Rank() row_limit = %q, want 3", got)
		}
	})
}

func newRankCapacityTestClient(t *testing.T, encoded []byte, requests *atomic.Int32, parameters *url.Values) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		if parameters != nil {
			*parameters = request.URL.Query()
		}
		_, _ = writer.Write(encoded)
	}))
	t.Cleanup(server.Close)
	return mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
}
