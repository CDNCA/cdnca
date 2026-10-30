package analytics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHandlerAuthenticationDeadlineAndCancellationContract(t *testing.T) {
	validActor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	path := handlerURL("/v1/analytics/summary", "")

	t.Run("caller cancellation fails closed before authentication", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion}}
		authCalls := 0
		handler := newAuthenticationDeadlineHandler(t, store, func(*http.Request) (Actor, error) {
			authCalls++
			return validActor, nil
		}, 50*time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		assertHandlerError(t, response, http.StatusRequestTimeout, "analytics_request_cancelled")
		if authCalls != 0 {
			t.Fatalf("authenticate calls = %d, want 0", authCalls)
		}
		if store.called {
			t.Fatal("store was called after caller cancellation")
		}
	})

	t.Run("caller deadline fails closed before authentication", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion}}
		authCalls := 0
		handler := newAuthenticationDeadlineHandler(t, store, func(*http.Request) (Actor, error) {
			authCalls++
			return validActor, nil
		}, 50*time.Millisecond)

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		assertHandlerError(t, response, http.StatusGatewayTimeout, "analytics_query_timeout")
		if authCalls != 0 {
			t.Fatalf("authenticate calls = %d, want 0", authCalls)
		}
		if store.called {
			t.Fatal("store was called after caller deadline")
		}
	})

	t.Run("caller deadline during authentication maps to query timeout", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion}}
		handler := newAuthenticationDeadlineHandler(t, store, func(request *http.Request) (Actor, error) {
			<-request.Context().Done()
			return Actor{}, errors.New("late private authentication error")
		}, 50*time.Millisecond)

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Millisecond))
		defer cancel()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))

		assertHandlerError(t, response, http.StatusGatewayTimeout, "analytics_query_timeout")
		if store.called {
			t.Fatal("store was called after caller deadline during authentication")
		}
	})

	t.Run("late private authentication error maps to query timeout", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion}}
		handler := newAuthenticationDeadlineHandler(t, store, func(request *http.Request) (Actor, error) {
			if _, ok := request.Context().Deadline(); !ok {
				return Actor{}, errors.New("late private authentication error")
			}
			<-request.Context().Done()
			return Actor{}, errors.New("late private authentication error")
		}, 10*time.Millisecond)

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		assertHandlerError(t, response, http.StatusGatewayTimeout, "analytics_query_timeout")
		if store.called {
			t.Fatal("store was called after authentication timeout")
		}
	})

	t.Run("timely authentication failure remains unauthorized", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion}}
		handler := newAuthenticationDeadlineHandler(t, store, func(*http.Request) (Actor, error) {
			return Actor{}, errors.New("private authentication error")
		}, 50*time.Millisecond)

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		assertHandlerError(t, response, http.StatusUnauthorized, "analytics_authentication_required")
		if store.called {
			t.Fatal("store was called after authentication failure")
		}
	})

	t.Run("authentication and store share one deadline", func(t *testing.T) {
		store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion, RequestCount: 1}}
		var authDeadline time.Time
		var authHasDeadline bool
		handler := newAuthenticationDeadlineHandler(t, store, func(request *http.Request) (Actor, error) {
			authDeadline, authHasDeadline = request.Context().Deadline()
			return validActor, nil
		}, 50*time.Millisecond)

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
		if !authHasDeadline || !store.hasDeadline {
			t.Fatalf("auth deadline present = %t, store deadline present = %t", authHasDeadline, store.hasDeadline)
		}
		if !authDeadline.Equal(store.deadline) {
			t.Fatalf("auth deadline = %s, store deadline = %s", authDeadline, store.deadline)
		}
	})

	for _, test := range []struct {
		name       string
		contextErr error
		wantStatus int
		wantCode   string
	}{
		{name: "cancellation", contextErr: context.Canceled, wantStatus: http.StatusRequestTimeout, wantCode: "analytics_request_cancelled"},
		{name: "deadline", contextErr: context.DeadlineExceeded, wantStatus: http.StatusGatewayTimeout, wantCode: "analytics_query_timeout"},
	} {
		t.Run("request context changes after service success/"+test.name, func(t *testing.T) {
			store := &authenticationDeadlineQueryStore{summary: Summary{MetricVersion: MetricVersion, RequestCount: 1}}
			parent := newPostServiceContext(4, test.contextErr)
			handler := newAuthenticationDeadlineHandler(t, store, func(*http.Request) (Actor, error) {
				return validActor, nil
			}, 50*time.Millisecond)

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(parent))

			assertHandlerError(t, response, test.wantStatus, test.wantCode)
			if !store.called {
				t.Fatal("store was not called before post-service context change")
			}
		})
	}
}

type authenticationDeadlineQueryStore struct {
	summary     Summary
	called      bool
	hasDeadline bool
	deadline    time.Time
}

func (store *authenticationDeadlineQueryStore) Summary(ctx context.Context, _ Scope, _ Filter) (Summary, error) {
	store.called = true
	store.deadline, store.hasDeadline = ctx.Deadline()
	return store.summary, nil
}

func (store *authenticationDeadlineQueryStore) Trend(context.Context, Scope, Filter) ([]TrendPoint, error) {
	return nil, nil
}

func (store *authenticationDeadlineQueryStore) Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error) {
	return RankPage{}, nil
}

func newAuthenticationDeadlineHandler(
	t *testing.T,
	store QueryStore,
	authenticate AuthenticateFunc,
	queryTimeout time.Duration,
) *Handler {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, authenticate, HandlerConfig{
		QueryTimeout: queryTimeout,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type postServiceContext struct {
	errAfter int
	err      error
	done     chan struct{}
	once     sync.Once
	calls    int
}

func newPostServiceContext(errAfter int, err error) context.Context {
	return &postServiceContext{errAfter: errAfter, err: err, done: make(chan struct{})}
}

func (context *postServiceContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (context *postServiceContext) Done() <-chan struct{} {
	return context.done
}

func (context *postServiceContext) Err() error {
	context.calls++
	if context.calls < context.errAfter {
		return nil
	}
	context.once.Do(func() { close(context.done) })
	return context.err
}

func (context *postServiceContext) Value(any) any {
	return nil
}
