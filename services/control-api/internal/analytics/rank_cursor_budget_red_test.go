package analytics

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type rankCursorBudgetHTTPClient struct {
	calls int
}

func (client *rankCursorBudgetHTTPClient) Do(*http.Request) (*http.Response, error) {
	client.calls++
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestRankRejectsNonCanonicalOrOverBudgetCursorBeforeDispatch(t *testing.T) {
	periodEnd := time.Now().UTC().Truncate(time.Hour)
	filter := Filter{From: periodEnd.Add(-time.Hour), To: periodEnd}
	fingerprint := rankFingerprint(AdminScope(), filter, RankByURL)
	base := rankCursor{
		Version: 1, Query: fingerprint, SnapshotMilli: periodEnd.UnixMilli(),
		ResponseBytes: 100, RequestCount: 1, Key: "/safe",
	}
	canonical, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	duplicateKey := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"k":"/safe"}`)...)
	overBudget := base
	overBudget.Key = strings.Repeat("x", maxRankKeyBytes+1)
	overBudgetRaw, err := json.Marshal(overBudget)
	if err != nil {
		t.Fatalf("marshal over-budget cursor: %v", err)
	}

	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{name: "duplicate known JSON key", raw: duplicateKey},
		{name: "decoded key exceeds budget", raw: overBudgetRaw},
	} {
		t.Run(test.name, func(t *testing.T) {
			cursor := base64.RawURLEncoding.EncodeToString(test.raw)
			if len(cursor) > maxCursorSize {
				t.Fatalf("fixture cursor length %d exceeds outer bound", len(cursor))
			}
			httpClient := &rankCursorBudgetHTTPClient{}
			client, err := NewClient(Config{Endpoint: "https://clickhouse.example.test", Database: "analytics_test"}, httpClient)
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			_, err = client.Rank(context.Background(), AdminScope(), filter, RankByURL, 10, cursor)
			if !errors.Is(err, ErrInvalidInput) || httpClient.calls != 0 {
				t.Fatalf("Rank() error=%v HTTP calls=%d, want ErrInvalidInput before dispatch", err, httpClient.calls)
			}
		})
	}
}
