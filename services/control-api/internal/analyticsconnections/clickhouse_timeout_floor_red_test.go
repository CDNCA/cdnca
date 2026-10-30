package analyticsconnections

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type clickHouseTimeoutClient struct {
	requests []*http.Request
}

func (client *clickHouseTimeoutClient) Do(request *http.Request) (*http.Response, error) {
	client.requests = append(client.requests, request)
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestClickHouseWriterFloorsEffectiveDispatchTimeout(t *testing.T) {
	receipt, err := ValidateDelivery(validConnectionsDelivery())
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	operations := []struct {
		name string
		run  func(context.Context, *ClickHouseWriter, Receipt) error
	}{
		{name: "lookup", run: func(ctx context.Context, writer *ClickHouseWriter, receipt Receipt) error {
			_, err := writer.lookup(ctx, receipt)
			return err
		}},
		{name: "insert", run: func(ctx context.Context, writer *ClickHouseWriter, receipt Receipt) error {
			return writer.insertRows(ctx, receipt)
		}},
	}
	tests := []struct {
		name             string
		configured       time.Duration
		callerTimeout    time.Duration
		wantMax          float64
		wantZeroDispatch bool
	}{
		{name: "whole milliseconds", configured: 10 * time.Millisecond, wantMax: 0.010},
		{name: "fractional configured milliseconds", configured: 1500 * time.Microsecond, wantMax: 0.001},
		{name: "caller deadline is smaller", configured: time.Second, callerTimeout: 100 * time.Millisecond, wantMax: 0.100},
		{name: "sub millisecond configured", configured: 500 * time.Microsecond, wantZeroDispatch: true},
		{name: "sub millisecond caller", configured: time.Second, callerTimeout: 500 * time.Microsecond, wantZeroDispatch: true},
	}
	for _, operation := range operations {
		for _, test := range tests {
			t.Run(operation.name+"/"+test.name, func(t *testing.T) {
				client := &clickHouseTimeoutClient{}
				writer, err := NewClickHouseWriter(ClickHouseConfig{
					Endpoint: "http://127.0.0.1:8123", Database: "analytics",
					OperationTimeout: test.configured, MaxResponseBytes: 8192,
				}, client)
				if err != nil {
					t.Fatalf("writer: %v", err)
				}
				ctx := context.Background()
				cancel := func() {}
				if test.callerTimeout > 0 {
					ctx, cancel = context.WithTimeout(ctx, test.callerTimeout)
				}
				defer cancel()
				err = operation.run(ctx, writer, receipt)
				if test.wantZeroDispatch {
					if !errors.Is(err, context.DeadlineExceeded) || len(client.requests) != 0 {
						t.Fatalf("err=%v requests=%d, want deadline exceeded before dispatch", err, len(client.requests))
					}
					return
				}
				if err != nil || len(client.requests) != 1 {
					t.Fatalf("err=%v requests=%d", err, len(client.requests))
				}
				encoded := client.requests[0].URL.Query().Get("max_execution_time")
				got, parseErr := strconv.ParseFloat(encoded, 64)
				if parseErr != nil || got <= 0 || got > test.wantMax {
					t.Fatalf("max_execution_time=%q parsed=%v err=%v, want positive value <= %.3f", encoded, got, parseErr, test.wantMax)
				}
			})
		}
	}
}
