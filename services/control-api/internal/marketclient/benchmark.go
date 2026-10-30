package marketclient

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// BenchmarkTask is one admission benchmark download the market asks one of
// this member's nodes to run (CAPABILITY_NAME_MARKET_BENCHMARK).
type BenchmarkTask struct {
	RoundID       uuid.UUID `json:"round_id"`
	ProberNodeID  string    `json:"prober_node_id"`
	TargetIP      string    `json:"target_ip"`
	Port          int       `json:"port"`
	Path          string    `json:"path"`
	Connections   int       `json:"connections"`
	TimeoutMillis int       `json:"timeout_millis"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// BenchmarkResult is one executed download; skipped ones are never submitted.
type BenchmarkResult struct {
	RoundID      uuid.UUID `json:"round_id"`
	ProberNodeID string    `json:"prober_node_id"`
	OK           bool      `json:"ok"`
	Kbps         int64     `json:"kbps"`
	TTFBMillis   int64     `json:"ttfb_ms"`
}

func (c *Client) BenchmarkTasks(ctx context.Context) ([]BenchmarkTask, error) {
	var response struct {
		Items []BenchmarkTask `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/benchmark/tasks", nil, &response, requestTimeout); err != nil {
		return nil, err
	}
	return response.Items, nil
}

func (c *Client) SubmitBenchmarkResults(ctx context.Context, results []BenchmarkResult) (int, error) {
	var response struct {
		Accepted int `json:"accepted"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/benchmark/results", map[string]any{"results": results}, &response, requestTimeout)
	return response.Accepted, err
}
