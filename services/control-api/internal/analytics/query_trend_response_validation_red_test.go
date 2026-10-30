package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrendRejectsInvalidResponseRowsFailClosed(t *testing.T) {
	from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	tests := []struct {
		name string
		rows []trendRow
	}{
		{name: "wrong metric version", rows: []trendRow{{BucketUnix: from.Unix(), MetricVersion: MetricVersion + 1}}},
		{name: "before from", rows: []trendRow{{BucketUnix: from.Add(-time.Hour).Unix(), MetricVersion: MetricVersion}}},
		{name: "at to", rows: []trendRow{{BucketUnix: to.Unix(), MetricVersion: MetricVersion}}},
		{name: "after to", rows: []trendRow{{BucketUnix: to.Add(time.Hour).Unix(), MetricVersion: MetricVersion}}},
		{name: "not whole hour", rows: []trendRow{{BucketUnix: from.Add(time.Minute).Unix(), MetricVersion: MetricVersion}}},
		{
			name: "duplicate bucket",
			rows: []trendRow{
				{BucketUnix: from.Unix(), MetricVersion: MetricVersion},
				{BucketUnix: from.Unix(), MetricVersion: MetricVersion},
			},
		},
		{
			name: "reverse order",
			rows: []trendRow{
				{BucketUnix: from.Add(time.Hour).Unix(), MetricVersion: MetricVersion},
				{BucketUnix: from.Unix(), MetricVersion: MetricVersion},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTrendResponseTestClient(t, test.rows)
			points, err := client.Trend(context.Background(), AdminScope(), Filter{From: from, To: to})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Trend() error = %v, want ErrInvalidResponse", err)
			}
			if points != nil {
				t.Fatalf("Trend() returned partial points: %#v", points)
			}
		})
	}
}

func TestTrendAcceptsEmptyAndStrictlyOrderedResponseRows(t *testing.T) {
	from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	tests := []struct {
		name string
		rows []trendRow
	}{
		{name: "empty"},
		{
			name: "ordered",
			rows: []trendRow{
				{BucketUnix: from.Unix(), MetricVersion: MetricVersion, RequestCount: 2},
				{BucketUnix: from.Add(2 * time.Hour).Unix(), MetricVersion: MetricVersion, RequestCount: 1},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTrendResponseTestClient(t, test.rows)
			points, err := client.Trend(context.Background(), AdminScope(), Filter{From: from, To: to})
			if err != nil {
				t.Fatalf("Trend() error = %v", err)
			}
			if len(points) != len(test.rows) {
				t.Fatalf("Trend() points = %#v, want %d rows", points, len(test.rows))
			}
			for index, row := range test.rows {
				wantHour := time.Unix(row.BucketUnix, 0).UTC()
				if !points[index].Hour.Equal(wantHour) || points[index].Hour.Location() != time.UTC ||
					points[index].MetricVersion != row.MetricVersion || points[index].RequestCount != row.RequestCount {
					t.Fatalf("Trend() point %d = %#v, want hour=%v version=%d request_count=%d",
						index, points[index], wantHour, row.MetricVersion, row.RequestCount)
				}
			}
		})
	}
}

func newTrendResponseTestClient(t *testing.T, rows []trendRow) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		encoder := json.NewEncoder(writer)
		for _, row := range rows {
			if err := encoder.Encode(row); err != nil {
				t.Errorf("encode trend row: %v", err)
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}
