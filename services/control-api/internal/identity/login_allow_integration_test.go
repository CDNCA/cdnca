package identity

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recordedAllow struct {
	scope, user       uuid.UUID
	source, requestID string
}

type allowRecorder struct {
	calls []recordedAllow
	fail  error
}

func (r *allowRecorder) AllowAdminLogin(_ context.Context, scope, user uuid.UUID, source, requestID string) error {
	r.calls = append(r.calls, recordedAllow{scope, user, source, requestID})
	return r.fail
}

// fix-adplatwire (ADR 0010 §7.2 item 3): a successful sign-in hands its
// source to the auto defense allow list; a failing recorder never fails the
// sign-in; a failed password never reaches it.
func TestLoginHandsSourceToAllowRecorderPostgres(t *testing.T) {
	databaseURL := os.Getenv("TEST_IDENTITY_DISPLAY_ID_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_IDENTITY_DISPLAY_ID_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var scopeID uuid.UUID
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES(gen_random_uuid(),'platform') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	username := "login-allow-" + userID.String()[:8]
	password := "login-allow-fixture-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status) VALUES ($1,$2,'Login allow',$3,'active')`,
		userID, username, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	tokens, err := NewTokenManager("login-allow-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &allowRecorder{fail: errors.New("recorder down")}
	service.SetLoginAllowRecorder(recorder)
	if _, err := service.Login(ctx, LoginInput{Username: username, Password: "wrong-password", ScopeID: &scopeID},
		RequestInfo{RequestID: "login-allow-bad", SourceIP: "203.0.113.9"}); err == nil {
		t.Fatal("wrong password signed in")
	}
	if len(recorder.calls) != 0 {
		t.Fatalf("failed sign-in reached the recorder: %+v", recorder.calls)
	}
	if _, err := service.Login(ctx, LoginInput{Username: username, Password: password, ScopeID: &scopeID},
		RequestInfo{RequestID: "login-allow-ok", SourceIP: "203.0.113.9"}); err != nil {
		t.Fatalf("a failing recorder failed the sign-in: %v", err)
	}
	want := recordedAllow{scopeID, userID, "203.0.113.9", "login-allow-ok"}
	if len(recorder.calls) != 1 || recorder.calls[0] != want {
		t.Fatalf("recorder calls %+v, want %+v", recorder.calls, want)
	}
}
