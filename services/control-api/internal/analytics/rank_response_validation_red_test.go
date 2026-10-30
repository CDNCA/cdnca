package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRankRejectsInvalidRowsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		rows []RankItem
	}{
		{
			name: "empty key",
			rows: []RankItem{{Key: "", RequestCount: 1, ResponseBytes: 100}},
		},
		{
			name: "ascii control key",
			rows: []RankItem{{Key: "/asset\x1f.js", RequestCount: 1, ResponseBytes: 100}},
		},
		{
			name: "unicode c1 control key",
			rows: []RankItem{{Key: "/asset\u0085.js", RequestCount: 1, ResponseBytes: 100}},
		},
		{
			name: "key exceeds maximum bytes",
			rows: []RankItem{{Key: strings.Repeat("x", maxRankKeyBytes+1), RequestCount: 1, ResponseBytes: 100}},
		},
		{
			name: "zero request count",
			rows: []RankItem{{Key: "/asset.js", RequestCount: 0, ResponseBytes: 100}},
		},
		{
			name: "duplicate key",
			rows: []RankItem{
				{Key: "/a", RequestCount: 2, ResponseBytes: 200},
				{Key: "/a", RequestCount: 1, ResponseBytes: 100},
			},
		},
		{
			name: "response bytes not descending",
			rows: []RankItem{
				{Key: "/a", RequestCount: 2, ResponseBytes: 100},
				{Key: "/b", RequestCount: 1, ResponseBytes: 101},
			},
		},
		{
			name: "request count not descending on response tie",
			rows: []RankItem{
				{Key: "/a", RequestCount: 1, ResponseBytes: 100},
				{Key: "/b", RequestCount: 2, ResponseBytes: 100},
			},
		},
		{
			name: "key not ascending on metric tie",
			rows: []RankItem{
				{Key: "/b", RequestCount: 1, ResponseBytes: 100},
				{Key: "/a", RequestCount: 1, ResponseBytes: 100},
			},
		},
		{
			name: "invalid hidden limit plus one row",
			rows: []RankItem{
				{Key: "/a", RequestCount: 2, ResponseBytes: 200},
				{Key: "/b", RequestCount: 1, ResponseBytes: 100},
				{Key: "", RequestCount: 1, ResponseBytes: 50},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newRankResponseTestClient(t, test.rows)
			page, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByURL, 2, "")
			assertRankInvalidResponse(t, page, err)
		})
	}
}

func TestRankRejectsRowsOutsideCursorWindowFailClosed(t *testing.T) {
	tests := []struct {
		name string
		row  RankItem
	}{
		{
			name: "equal to cursor",
			row:  RankItem{Key: "/b", RequestCount: 4, ResponseBytes: 90},
		},
		{
			name: "higher response bytes",
			row:  RankItem{Key: "/a", RequestCount: 5, ResponseBytes: 100},
		},
		{
			name: "higher request count on response tie",
			row:  RankItem{Key: "/x", RequestCount: 5, ResponseBytes: 90},
		},
		{
			name: "lower key on metric tie",
			row:  RankItem{Key: "/a", RequestCount: 4, ResponseBytes: 90},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstRows := []RankItem{
				{Key: "/a", RequestCount: 5, ResponseBytes: 100},
				{Key: "/b", RequestCount: 4, ResponseBytes: 90},
				{Key: "/c", RequestCount: 3, ResponseBytes: 80},
			}
			responses := [][]byte{rankRowsJSON(t, firstRows), rankRowsJSON(t, []RankItem{test.row})}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if calls >= len(responses) {
					writer.WriteHeader(http.StatusInternalServerError)
					return
				}
				_, _ = writer.Write(responses[calls])
				calls++
			}))
			t.Cleanup(server.Close)
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			filter := validFilter()
			first, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 2, "")
			if err != nil || first.NextCursor == "" {
				t.Fatalf("first page = %#v, error = %v", first, err)
			}
			page, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 2, first.NextCursor)
			assertRankInvalidResponse(t, page, err)
		})
	}
}

func newRankResponseTestClient(t *testing.T, rows []RankItem) *Client {
	t.Helper()
	body := rankRowsJSON(t, rows)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
}

func rankRowsJSON(t *testing.T, rows []RankItem) []byte {
	t.Helper()
	var body []byte
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, encoded...)
		body = append(body, '\n')
	}
	return body
}

func assertRankInvalidResponse(t *testing.T, page RankPage, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Rank() error = %v, want ErrInvalidResponse", err)
	}
	if len(page.Items) != 0 || page.NextCursor != "" || !page.SnapshotAt.IsZero() {
		t.Fatalf("Rank() returned partial page: %#v", page)
	}
}
