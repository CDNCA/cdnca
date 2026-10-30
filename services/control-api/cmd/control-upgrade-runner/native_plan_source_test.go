package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/google/uuid"
)

func TestNativeHTTPPlanSourceRequiresBoundEmptyPublication(t *testing.T) {
	installationID := uuid.NewString()
	for _, test := range []struct {
		name, installation, operation, etag string
		status                              int
		cached                              bool
		want                                error
	}{
		{name: "no plan", installation: installationID, operation: controlplaneupgrade.SystemdControlUpgradeOperation, status: 204, want: ErrHTTPPlanNotPublished},
		{name: "wrong installation", installation: uuid.NewString(), operation: controlplaneupgrade.SystemdControlUpgradeOperation, status: 204, want: ErrHTTPPlanSourceConflict},
		{name: "missing operation", installation: installationID, status: 204, want: ErrHTTPPlanSourceConflict},
		{name: "unexpected etag", installation: installationID, operation: controlplaneupgrade.SystemdControlUpgradeOperation, etag: `"0"`, status: 204, want: ErrHTTPPlanSourceConflict},
		{name: "lost prior publication", installation: installationID, operation: controlplaneupgrade.SystemdControlUpgradeOperation, status: 204, cached: true, want: ErrHTTPPlanSourceConflict},
		{name: "unauthorized", status: 401, want: ErrHTTPPlanSourceUnavailable},
		{name: "unavailable", status: 503, want: ErrHTTPPlanSourceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(controlplaneupgradehttp.SystemdPlanInstallationHeader, test.installation)
				w.Header().Set(controlplaneupgradehttp.SystemdPlanOperationHeader, test.operation)
				w.Header().Set("ETag", test.etag)
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			source := newHTTPPlanSourceForTest(t, server, installationID, 1024, time.Second)
			if test.cached {
				cached := ops06HTTPPlan([]byte(`{"signed":"prior"}`), 1)
				source.cached = &cached
			}
			plan, err := source.Fetch(t.Context())
			if !errors.Is(err, test.want) || len(plan.Bundle) != 0 {
				t.Fatalf("empty response accepted incorrectly err=%v want=%v", err, test.want)
			}
		})
	}
}

func TestNativePlanSourceHealthRequiresRecentActualReadAndFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	currentError := ErrHTTPPlanNotPublished
	source := &nativePlanSource{source: nativePlanFetcherFunc(func(context.Context) (HTTPPlan, error) {
		return HTTPPlan{}, currentError
	}), now: func() time.Time { return now }}
	if source.Ready() {
		t.Fatal("unconfirmed source ready")
	}
	if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanNotPublished) || !source.Ready() {
		t.Fatalf("authenticated empty repository not healthy: %v", err)
	}
	now = now.Add(31 * time.Second)
	if source.Ready() {
		t.Fatal("stale source ready")
	}
	currentError = nil
	if _, err := source.Fetch(t.Context()); err != nil || !source.Ready() {
		t.Fatalf("successful read not healthy: %v", err)
	}
	currentError = ErrHTTPPlanSourceUnavailable
	_, _ = source.Fetch(t.Context())
	if source.Ready() {
		t.Fatal("source failure did not clear readiness")
	}
}

func TestNativeUnpublishedPlanWaitsWithoutExecutionOrFailureLog(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var logs bytes.Buffer
	runner := &ops06PlanRunner{}
	source := nativePlanFetcherFunc(func(context.Context) (HTTPPlan, error) {
		cancel()
		return HTTPPlan{}, ErrHTTPPlanNotPublished
	})
	err := runPlanLoop(ctx, source, &ops06LKGWriter{}, nil, runner, func([]byte) error { return nil },
		time.Millisecond, false, slog.New(slog.NewTextHandler(&logs, nil)))
	if !errors.Is(err, context.Canceled) || len(runner.bundles) != 0 || logs.Len() != 0 {
		t.Fatalf("no publication executed or logged as failure: err=%v logs=%q", err, logs.String())
	}
}

type nativePlanFetcherFunc func(context.Context) (HTTPPlan, error)

func (fetch nativePlanFetcherFunc) Fetch(ctx context.Context) (HTTPPlan, error) { return fetch(ctx) }
