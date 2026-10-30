package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// This only adds a readiness requirement. Local release and root-process
// verification remain mandatory in NativeStandaloneRunner.Probe.
type nativePlanSource struct {
	source      httpPlanFetcher
	now         func() time.Time
	lastSuccess atomic.Int64
}

func (source *nativePlanSource) Fetch(ctx context.Context) (HTTPPlan, error) {
	plan, err := source.source.Fetch(ctx)
	observed := int64(0)
	if err == nil || errors.Is(err, ErrHTTPPlanNotPublished) {
		observed = source.now().UnixNano()
	}
	source.lastSuccess.Store(observed)
	return plan, err
}

func (source *nativePlanSource) Ready() bool {
	last := source.lastSuccess.Load()
	if last == 0 {
		return false
	}
	age := source.now().Sub(time.Unix(0, last))
	return age >= 0 && age <= 30*time.Second
}
