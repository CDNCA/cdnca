package dashboard

import (
	"context"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultProductionQueryTimeout = 5 * time.Second
	maximumProductionQueryTimeout = 30 * time.Second
	defaultProductionConcurrency  = 32
	maximumProductionConcurrency  = 256
)

type ProductionConfig struct {
	QueryTimeout  time.Duration
	MaxConcurrent int
}

type ProductionDependencies struct {
	Pool       *pgxpool.Pool
	Authorizer *iamlock.Authorizer
	Analytics  AnalyticsReader
}

type ProductionReader struct {
	source       Reader
	queryTimeout time.Duration
	capacity     chan struct{}
}

func NewProductionStore(config ProductionConfig, dependencies ProductionDependencies) (*ProductionReader, error) {
	analyticsReader := dependencies.Analytics
	if interfaceNil(analyticsReader) {
		analyticsReader = nil
	}
	store, err := NewStore(dependencies.Pool, dependencies.Authorizer, analyticsReader)
	if err != nil {
		return nil, err
	}
	store.parallelAnalytics = true
	return NewProductionReader(store, config)
}

func NewProductionReader(source Reader, config ProductionConfig) (*ProductionReader, error) {
	if interfaceNil(source) {
		return nil, ErrInvalidConfig
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultProductionQueryTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultProductionConcurrency
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumProductionQueryTimeout ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > maximumProductionConcurrency {
		return nil, ErrInvalidConfig
	}
	return &ProductionReader{
		source: source, queryTimeout: config.QueryTimeout,
		capacity: make(chan struct{}, config.MaxConcurrent),
	}, nil
}

func (reader *ProductionReader) Admin(ctx context.Context, actor Actor, query Query) (AdminResponse, error) {
	readCtx, release, err := reader.begin(ctx)
	if err != nil {
		return AdminResponse{}, err
	}
	defer release()
	response, err := reader.source.Admin(readCtx, actor, query)
	if contextErr := readCtx.Err(); contextErr != nil {
		return AdminResponse{}, contextErr
	}
	return response, err
}

func (reader *ProductionReader) Tenant(ctx context.Context, actor Actor, query Query) (TenantResponse, error) {
	readCtx, release, err := reader.begin(ctx)
	if err != nil {
		return TenantResponse{}, err
	}
	defer release()
	response, err := reader.source.Tenant(readCtx, actor, query)
	if contextErr := readCtx.Err(); contextErr != nil {
		return TenantResponse{}, contextErr
	}
	return response, err
}

func (reader *ProductionReader) begin(ctx context.Context) (context.Context, func(), error) {
	if reader == nil || interfaceNil(reader.source) || reader.queryTimeout < time.Millisecond || reader.capacity == nil || ctx == nil {
		return nil, nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case reader.capacity <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		return nil, nil, ErrUnavailable
	}
	readCtx, cancel := context.WithTimeout(ctx, reader.queryTimeout)
	return readCtx, func() {
		cancel()
		<-reader.capacity
	}, nil
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ Reader = (*ProductionReader)(nil)
