//go:build integration

package identity_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// TestConcurrentRefreshWithSameCookieKeepsSession reproduces "kicked out after
// a while": two tabs (or a page load racing the renewal timer) post
// /v1/auth/refresh with the same cookie. Before the fix the second request hit
// the replay branch, revoked the whole family and every tab had to sign in again.
func TestConcurrentRefreshWithSameCookieKeepsSession(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	login, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "concurrent-login", SourceIP: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}

	const tabs = 4
	results := make([]identity.AuthResult, tabs)
	errs := make([]error, tabs)
	var wait sync.WaitGroup
	for index := range tabs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = fixture.service.Refresh(ctx, login.RefreshToken,
				identity.RequestInfo{RequestID: "concurrent-refresh", SourceIP: "192.0.2.10"})
		}()
	}
	wait.Wait()

	rotated := ""
	for index := range tabs {
		if errs[index] != nil {
			t.Fatalf("tab %d refresh: %v (concurrent refresh with one cookie must not end the session)", index, errs[index])
		}
		if _, err := fixture.service.Authenticate(ctx, results[index].AccessToken); err != nil {
			t.Fatalf("tab %d access token: %v", index, err)
		}
		if results[index].RefreshToken != "" {
			if rotated != "" {
				t.Fatalf("more than one tab rotated the refresh token")
			}
			rotated = results[index].RefreshToken
		}
	}
	if rotated == "" {
		t.Fatal("no tab rotated the refresh token")
	}
	// The rotated cookie keeps working afterwards.
	next, err := fixture.service.Refresh(ctx, rotated, identity.RequestInfo{RequestID: "after-concurrent", SourceIP: "192.0.2.10"})
	if err != nil || next.RefreshToken == "" {
		t.Fatalf("refresh with rotated cookie: %v", err)
	}
	var revoked int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL`).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 {
		t.Fatalf("revoked sessions = %d, want 0", revoked)
	}
}

// TestRefreshReplayAfterSuccessorUsedStillRevokes: the grace only covers a
// sibling request; once the successor itself was rotated, presenting the
// original token again is replay and revokes the family.
func TestRefreshReplayAfterSuccessorUsedStillRevokes(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	login, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "replay-login", SourceIP: "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.service.Refresh(ctx, login.RefreshToken, identity.RequestInfo{RequestID: "replay-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Refresh(ctx, first.RefreshToken, identity.RequestInfo{RequestID: "replay-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Refresh(ctx, login.RefreshToken, identity.RequestInfo{RequestID: "replay-3"}); !errors.Is(err, identity.ErrRefreshReplay) {
		t.Fatalf("replayed original token: %v, want ErrRefreshReplay", err)
	}
	var reason string
	if err := fixture.pool.QueryRow(ctx, `SELECT DISTINCT revocation_reason FROM auth_sessions`).Scan(&reason); err != nil || reason != "refresh_replay" {
		t.Fatalf("revocation reason = %q, %v", reason, err)
	}
}

// TestRefreshAfterGraceIsReplay: outside the grace window the old token is replay.
func TestRefreshAfterGraceIsReplay(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	login, err := fixture.service.Login(ctx, identity.LoginInput{Username: fixture.username, Password: fixture.password},
		identity.RequestInfo{RequestID: "grace-login", SourceIP: "192.0.2.12"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Refresh(ctx, login.RefreshToken, identity.RequestInfo{RequestID: "grace-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE auth_sessions SET used_at = used_at - interval '31 seconds' WHERE used_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Refresh(ctx, login.RefreshToken, identity.RequestInfo{RequestID: "grace-2"}); !errors.Is(err, identity.ErrRefreshReplay) {
		t.Fatalf("old token after grace: %v, want ErrRefreshReplay", err)
	}
}
