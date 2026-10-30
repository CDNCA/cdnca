package analyticslog

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeHandlerRejectsOversizeRawQueryBeforeDependencies(t *testing.T) {
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()

	var authenticationCalls atomic.Int64
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		authenticationCalls.Add(1)
		return Principal{}, errors.New("invalid credentials")
	}, authorizer, time.Second)

	for _, path := range []string{
		"/v1/analytics/logs/access",
		"/v1/analytics/logs/block-events",
		"/v1/analytics/logs/blocks/current",
		"/v1/analytics/logs/blocks/history",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet,
				path+"?"+strings.Repeat("x", maximumRawQueryBytes+1), nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
		})
	}

	if authenticationCalls.Load() != 0 || len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("oversize query reached dependencies: authentication=%d authorization=%d storage=%d",
			authenticationCalls.Load(), len(authorizer.calls()), storageCalls.Load())
	}
}

func TestRuntimeHandlerAllowsExactRawQueryCapToReachAuthentication(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	var authenticationCalls atomic.Int64
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		authenticationCalls.Add(1)
		return Principal{}, errors.New("invalid credentials")
	}, authorizer, time.Second)
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/access?"+strings.Repeat("x", maximumRawQueryBytes), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertHandlerError(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
	if authenticationCalls.Load() != 1 || len(authorizer.calls()) != 0 {
		t.Fatalf("exact-cap query dependency calls: authentication=%d authorization=%d",
			authenticationCalls.Load(), len(authorizer.calls()))
	}
}
