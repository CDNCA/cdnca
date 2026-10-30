package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRealtimeRejectsNonAtomicProjection(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	tests := []struct {
		name   string
		mutate func(*RealtimeResult)
	}{
		{name: "observed evidence differs from access summary", mutate: func(result *RealtimeResult) {
			result.Evidence.ObservedEvents = 11
			result.Evidence.ExpectedEvents = 11
		}},
		{name: "minute series differs from summary", mutate: func(result *RealtimeResult) {
			result.Series[0].Requests = 11
			result.Series[0].TrafficBytes = 1100
		}},
		{name: "ranking exceeds summary", mutate: func(result *RealtimeResult) {
			result.Top[0].Requests = 13
			result.Top[0].TrafficBytes = 1300
		}},
		{name: "ranking ties are not canonical", mutate: func(result *RealtimeResult) {
			result.Top = []RealtimeTopItem{
				{Host: "z.example.test", ListenPort: 443, Requests: 6, TrafficBytes: 600},
				{Host: "a.example.test", ListenPort: 443, Requests: 6, TrafficBytes: 600},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validRealtimeResult(from, to)
			test.mutate(&result)
			result.Evidence.ErrorPPM = realtimeErrorPPM(result.Evidence.ExpectedEvents, result.Evidence.ObservedEvents)
			if err := validateRealtimeResult(result, RealtimeFilter{From: from, To: to}); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("validateRealtimeResult() error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

type cancelingRealtimeStore struct {
	result RealtimeResult
}

func (*cancelingRealtimeStore) Summary(context.Context, Scope, Filter) (Summary, error) {
	return Summary{}, nil
}

func (*cancelingRealtimeStore) Trend(context.Context, Scope, Filter) ([]TrendPoint, error) {
	return nil, nil
}

func (*cancelingRealtimeStore) Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error) {
	return RankPage{}, nil
}

func (store *cancelingRealtimeStore) Realtime(ctx context.Context, _ Scope, _ RealtimeFilter) (RealtimeResult, error) {
	if cancel, ok := ctx.Value(cancelContextKey{}).(context.CancelFunc); ok {
		cancel()
	}
	return store.result, nil
}

type cancelContextKey struct{}

func TestRealtimePreservesCancellationAfterStoreReturns(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, cancelContextKey{}, context.CancelFunc(cancel))
	service, err := NewService(&cancelingRealtimeStore{result: validRealtimeResult(from, from.Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Realtime(ctx, Actor{ScopeKind: "tenant", TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}},
		RealtimeRequest{Audience: AudienceTenant, From: from, To: from.Add(time.Hour)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Realtime() error = %v, want context.Canceled", err)
	}
}
