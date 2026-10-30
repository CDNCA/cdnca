package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"
)

type productionReaderStub struct {
	adminResponse  AdminResponse
	tenantResponse TenantResponse
	err            error
	entered        chan struct{}
	release        chan struct{}
	adminActor     Actor
	adminQuery     Query
	tenantActor    Actor
	tenantQuery    Query
}

func (stub *productionReaderStub) Admin(ctx context.Context, actor Actor, query Query) (AdminResponse, error) {
	stub.adminActor, stub.adminQuery = actor, query
	if stub.entered != nil {
		stub.entered <- struct{}{}
	}
	if stub.release != nil {
		select {
		case <-stub.release:
		case <-ctx.Done():
			return AdminResponse{}, ctx.Err()
		}
	}
	return stub.adminResponse, stub.err
}

func (stub *productionReaderStub) Tenant(ctx context.Context, actor Actor, query Query) (TenantResponse, error) {
	stub.tenantActor, stub.tenantQuery = actor, query
	if stub.entered != nil {
		stub.entered <- struct{}{}
	}
	if stub.release != nil {
		select {
		case <-stub.release:
		case <-ctx.Done():
			return TenantResponse{}, ctx.Err()
		}
	}
	return stub.tenantResponse, stub.err
}

func TestNewProductionReaderFailsClosedForInvalidSourceAndFences(t *testing.T) {
	valid := &productionReaderStub{}
	var typedNil *productionReaderStub
	for _, test := range []struct {
		name   string
		source Reader
		config ProductionConfig
	}{
		{name: "nil source", config: ProductionConfig{QueryTimeout: time.Second, MaxConcurrent: 1}},
		{name: "typed nil source", source: typedNil, config: ProductionConfig{QueryTimeout: time.Second, MaxConcurrent: 1}},
		{name: "sub millisecond timeout", source: valid, config: ProductionConfig{QueryTimeout: time.Nanosecond, MaxConcurrent: 1}},
		{name: "oversized timeout", source: valid, config: ProductionConfig{QueryTimeout: 31 * time.Second, MaxConcurrent: 1}},
		{name: "negative capacity", source: valid, config: ProductionConfig{QueryTimeout: time.Second, MaxConcurrent: -1}},
		{name: "oversized capacity", source: valid, config: ProductionConfig{QueryTimeout: time.Second, MaxConcurrent: 257}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, err := NewProductionReader(test.source, test.config)
			if reader != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewProductionReader() = %#v, %v", reader, err)
			}
		})
	}
}

func TestProductionReaderPreservesActorQueryAndAppliesTotalTimeout(t *testing.T) {
	source := &productionReaderStub{release: make(chan struct{})}
	reader, err := NewProductionReader(source, ProductionConfig{QueryTimeout: 10 * time.Millisecond, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ScopeKind: "tenant"}
	query := Query{Range: "custom", Timezone: "UTC", From: time.Now().UTC().Add(-time.Hour), To: time.Now().UTC()}
	_, err = reader.Tenant(t.Context(), actor, query)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Tenant() error = %v, want total deadline", err)
	}
	if source.tenantActor != actor || source.tenantQuery != query {
		t.Fatalf("source received actor=%#v query=%#v", source.tenantActor, source.tenantQuery)
	}
}

func TestProductionReaderRejectsExcessCapacityWithoutStartingSource(t *testing.T) {
	source := &productionReaderStub{
		adminResponse: AdminResponse{DashboardVersion: Version},
		entered:       make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
	reader, err := NewProductionReader(source, ProductionConfig{QueryTimeout: time.Second, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}

	first := make(chan error, 1)
	go func() {
		_, callErr := reader.Admin(context.Background(), Actor{}, Query{})
		first <- callErr
	}()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("first read did not enter the source")
	}

	if _, err := reader.Admin(t.Context(), Actor{}, Query{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("excess capacity error = %v", err)
	}
	select {
	case <-source.entered:
		t.Fatal("capacity-rejected read reached the source")
	default:
	}
	close(source.release)
	if err := <-first; err != nil {
		t.Fatalf("first read error = %v", err)
	}
}
