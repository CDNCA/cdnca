package entitlementrefreshhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type fakeSyncer struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
	err     error
}

func (s *fakeSyncer) SyncOnce(context.Context) (entitlementguard.Snapshot, error) {
	s.calls.Add(1)
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		<-s.release
	}
	if s.err != nil {
		return entitlementguard.Snapshot{}, s.err
	}
	return entitlementguard.Snapshot{InstallationID: "installation-1", Serial: 7, KeyID: "key-1", Status: "valid", VerifiedAt: time.Unix(10, 0).UTC()}, nil
}

func testAuth(scope string, permissions ...string) AuthenticateFunc {
	return func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: scope, Permissions: permissions,
		}}, nil
	}
}

func request() *http.Request {
	r := httptest.NewRequest(http.MethodPost, Route, nil)
	r.Header.Set("Authorization", "Bearer access")
	r.Header.Set("X-Request-ID", "refresh-1")
	r.Header.Set("Idempotency-Key", "refresh-1")
	return r
}

func TestHandlerRefreshesOnlyPlatformAdminAndReturnsSnapshot(t *testing.T) {
	syncer := &fakeSyncer{}
	var audited bool
	handler, err := New(syncer, testAuth("platform", "platform.admin"), func(_ context.Context, _ identity.AuthenticatedSession, requestID, result, _ string, snapshot entitlementguard.Snapshot) error {
		audited = requestID == "refresh-1" && result == "success" && snapshot.Serial == 7
		return nil
	})
	require.NoError(t, err)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request())
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"schema":"`+Schema+`"`)
	require.Contains(t, response.Body.String(), `"serial":7`)
	require.Equal(t, int32(1), syncer.calls.Load())
	require.True(t, audited)
}

func TestHandlerRejectsUnauthenticatedAndNonPlatform(t *testing.T) {
	syncer := &fakeSyncer{}
	unauthenticated, err := New(syncer, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("invalid")
	})
	require.NoError(t, err)
	response := httptest.NewRecorder()
	unauthenticated.ServeHTTP(response, request())
	require.Equal(t, http.StatusUnauthorized, response.Code)

	nonPlatform, err := New(syncer, testAuth("tenant", "platform.admin"))
	require.NoError(t, err)
	response = httptest.NewRecorder()
	nonPlatform.ServeHTTP(response, request())
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Equal(t, int32(0), syncer.calls.Load())
}

func TestHandlerRejectsConcurrentRefreshAndMapsFailure(t *testing.T) {
	syncer := &fakeSyncer{started: make(chan struct{}, 1), release: make(chan struct{})}
	handler, err := New(syncer, testAuth("platform", "platform.admin"))
	require.NoError(t, err)
	firstDone := make(chan struct{})
	go func() {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request())
		close(firstDone)
	}()
	<-syncer.started
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request())
	require.Equal(t, http.StatusConflict, response.Code)
	close(syncer.release)
	<-firstDone

	failing, err := New(&fakeSyncer{err: errors.New("license service unavailable")}, testAuth("platform", "platform.admin"))
	require.NoError(t, err)
	response = httptest.NewRecorder()
	failing.ServeHTTP(response, request())
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.Contains(t, response.Body.String(), "entitlement_refresh_failed")
}

// B18 (LIC-REC-03): in progress, definite failure and unknown result keep
// distinct codes and every error carries the request ID.
func TestHandlerSeparatesUnknownResultAndCarriesRequestID(t *testing.T) {
	timeout, err := New(&fakeSyncer{err: context.DeadlineExceeded}, testAuth("platform", "platform.admin"))
	require.NoError(t, err)
	response := httptest.NewRecorder()
	timeout.ServeHTTP(response, request())
	require.Equal(t, http.StatusGatewayTimeout, response.Code)
	require.Contains(t, response.Body.String(), `"code":"entitlement_refresh_timeout"`)
	require.Contains(t, response.Body.String(), `"request_id":"refresh-1"`)

	failing, err := New(&fakeSyncer{err: errors.New("license service refused")}, testAuth("platform", "platform.admin"))
	require.NoError(t, err)
	response = httptest.NewRecorder()
	failing.ServeHTTP(response, request())
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.Contains(t, response.Body.String(), `"request_id":"refresh-1"`)

	auditFails, err := New(&fakeSyncer{}, testAuth("platform", "platform.admin"),
		func(context.Context, identity.AuthenticatedSession, string, string, string, entitlementguard.Snapshot) error {
			return errors.New("audit down")
		})
	require.NoError(t, err)
	response = httptest.NewRecorder()
	auditFails.ServeHTTP(response, request())
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), `"code":"entitlement_refresh_audit_failed"`)
	require.Contains(t, response.Body.String(), `"request_id":"refresh-1"`)
}

// LIC-REC-03 (report B): a COMMIT whose answer was lost may have installed the
// lease; it must not be reported as "not refreshed". Every refresh error says
// whether the lease was not applied, may have been applied, or was applied.
func TestHandlerLostCommitAcknowledgementIsUnknownNotFailure(t *testing.T) {
	lost := fmt.Errorf("install local entitlement: %w: %w", entitlementguard.ErrInstallOutcomeUnknown, io.ErrUnexpectedEOF)
	var auditedResult string
	handler, err := New(&fakeSyncer{err: lost}, testAuth("platform", "platform.admin"),
		func(_ context.Context, _ identity.AuthenticatedSession, _, result, outcome string, _ entitlementguard.Snapshot) error {
			auditedResult = result + "/" + outcome
			return nil
		})
	require.NoError(t, err)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request())
	require.NotContains(t, response.Body.String(), `"code":"entitlement_refresh_failed"`)
	require.Equal(t, http.StatusBadGateway, response.Code)
	require.Contains(t, response.Body.String(), `"code":"entitlement_refresh_unknown"`)
	require.Contains(t, response.Body.String(), `"outcome":"unknown"`)
	require.Contains(t, response.Body.String(), `"request_id":"refresh-1"`)
	require.Equal(t, "failure/unknown", auditedResult)
}

func TestHandlerErrorOutcomes(t *testing.T) {
	auditDown := func(context.Context, identity.AuthenticatedSession, string, string, string, entitlementguard.Snapshot) error {
		return errors.New("audit down")
	}
	for _, test := range []struct {
		name    string
		syncErr error
		audit   AuditFunc
		status  int
		code    string
		outcome string
	}{
		{"rolled back before commit", errors.New("license service refused"), nil, http.StatusBadGateway, "entitlement_refresh_failed", "not_applied"},
		{"deadline", context.DeadlineExceeded, nil, http.StatusGatewayTimeout, "entitlement_refresh_timeout", "unknown"},
		{"installed then audit failed", nil, auditDown, http.StatusServiceUnavailable, "entitlement_refresh_audit_failed", "applied"},
		{"failed then audit failed", errors.New("license service refused"), auditDown, http.StatusServiceUnavailable, "entitlement_refresh_audit_failed", "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var handler *Handler
			var err error
			if test.audit != nil {
				handler, err = New(&fakeSyncer{err: test.syncErr}, testAuth("platform", "platform.admin"), test.audit)
			} else {
				handler, err = New(&fakeSyncer{err: test.syncErr}, testAuth("platform", "platform.admin"))
			}
			require.NoError(t, err)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request())
			require.Equal(t, test.status, response.Code)
			require.Contains(t, response.Body.String(), `"code":"`+test.code+`"`)
			require.Contains(t, response.Body.String(), `"outcome":"`+test.outcome+`"`)
		})
	}
}
