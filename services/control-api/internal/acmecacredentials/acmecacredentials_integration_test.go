//go:build integration

package acmecacredentials_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func eabPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" || strings.TrimSpace(os.Getenv("TEST_DATABASE_TEMPLATE")) == "" {
		t.Skip("TEST_DATABASE_URL and TEST_DATABASE_TEMPLATE are required")
	}
	return databasetest.ClonedMigratedPool(t, nil)
}

func exec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[:3], " "), err)
	}
}

func platformActor(t *testing.T, pool *pgxpool.Pool, permissions ...string) acmecacredentials.Actor {
	t.Helper()
	var platform uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
		exec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	} else if err != nil {
		t.Fatal(err)
	}
	user, role := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status) VALUES($1,$2,'eab','unused','active')`,
		user, "eab-"+strings.ReplaceAll(user.String(), "-", "")[:16])
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, platform, user)
	if len(permissions) != 0 {
		exec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'eab',true)`,
			role, platform, "eab_"+strings.ReplaceAll(role.String(), "-", "")[:16])
		exec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`, role, permissions)
		exec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platform, user, role)
	}
	return acmecacredentials.Actor{UserID: user, ScopeID: platform, ScopeKind: "platform"}
}

// Credentials are sealed with the DNS keyring and readable only by the
// worker's resolver; the API view and the audit never carry the key;
// revisions guard concurrent writers; the configured issuer picks its CA's
// directory only once credentials exist.
func TestEABCredentialsSealAuditAndResolve(t *testing.T) {
	pool := eabPool(t)
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-key-1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := acmecacredentials.NewStore(pool, cipher, audit.New(pool), func() time.Time { return time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	manager := platformActor(t, pool, "system_configuration.manage", "system_configuration.read")
	reader := platformActor(t, pool, "system_configuration.read")
	hmacKey := bytes.Repeat([]byte{0xa5}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(hmacKey)
	if _, err := store.Save(t.Context(), reader, acmecacredentials.SaveRequest{CA: acmecacredentials.CAZeroSSL, KeyID: "kid-1", HMACKey: encoded, RequestID: "r1"}); !errors.Is(err, acmecacredentials.ErrPermissionDenied) {
		t.Fatalf("reader save: %v", err)
	}
	for _, bad := range []acmecacredentials.SaveRequest{
		{CA: "lets_encrypt", KeyID: "kid", HMACKey: encoded, RequestID: "r"},
		{CA: acmecacredentials.CAZeroSSL, KeyID: "", HMACKey: encoded, RequestID: "r"},
		{CA: acmecacredentials.CAZeroSSL, KeyID: "kid", HMACKey: "short", RequestID: "r"},
		{CA: acmecacredentials.CAZeroSSL, KeyID: "kid", HMACKey: encoded, Clear: true, RequestID: "r"},
	} {
		if _, err := store.Save(t.Context(), manager, bad); !errors.Is(err, acmecacredentials.ErrInvalidInput) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	view, err := store.Save(t.Context(), manager, acmecacredentials.SaveRequest{CA: acmecacredentials.CAZeroSSL, KeyID: "kid-1", HMACKey: encoded + "==", RequestID: "r2"})
	if err != nil || !view.Configured || view.Revision != 1 || view.KeyID != "kid-1" || len(view.HMACKeyPrefix) != 8 {
		t.Fatalf("save = %+v, %v", view, err)
	}
	if _, err := store.Save(t.Context(), manager, acmecacredentials.SaveRequest{CA: acmecacredentials.CAZeroSSL, KeyID: "kid-2", HMACKey: encoded, RequestID: "r3"}); !errors.Is(err, acmecacredentials.ErrRevisionConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	listed, err := store.List(t.Context(), reader)
	if err != nil || len(listed) != 2 || !listed[0].Configured || listed[1].Configured || listed[1].CA != acmecacredentials.CAGoogleTrust {
		t.Fatalf("list = %+v, %v", listed, err)
	}
	var ciphertext []byte
	var auditRaw string
	if err := pool.QueryRow(t.Context(), `SELECT eab_hmac_ciphertext FROM acme_ca_credentials WHERE ca='zerossl'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, hmacKey) {
		t.Fatal("HMAC key stored in clear")
	}
	if err := pool.QueryRow(t.Context(), `SELECT payload::text || changes::text FROM audit_events WHERE action='acme.ca_credential.update'`).Scan(&auditRaw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditRaw, encoded) || !strings.Contains(auditRaw, "kid-1") {
		t.Fatalf("audit = %s", auditRaw)
	}

	resolver, err := acmecacredentials.NewResolver(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	keyID, key, found, err := resolver.ExternalAccountBinding(context.Background(), acmecacredentials.Directory(acmecacredentials.CAZeroSSL))
	if err != nil || !found || keyID != "kid-1" || !bytes.Equal(key, hmacKey) {
		t.Fatalf("resolve = %q %x %v %v", keyID, key, found, err)
	}
	if _, _, found, err := resolver.ExternalAccountBinding(context.Background(), "https://acme-v02.api.letsencrypt.org/directory"); err != nil || found {
		t.Fatalf("LE has no EAB: %v %v", found, err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for issuer, want := range map[string]string{"lets_encrypt": "https://le.example/dir", acmecacredentials.CAZeroSSL: acmecacredentials.Directory(acmecacredentials.CAZeroSSL)} {
			got, err := resolver.DirectoryForIssuer(t.Context(), tx, issuer, "https://le.example/dir")
			if err != nil || got != want {
				t.Fatalf("issuer %s directory = %q, %v", issuer, got, err)
			}
		}
		if _, err := resolver.DirectoryForIssuer(t.Context(), tx, acmecacredentials.CAGoogleTrust, "https://le.example/dir"); !errors.Is(err, acmecacredentials.ErrNotConfigured) {
			t.Fatalf("google trust without credentials: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := store.Save(t.Context(), manager, acmecacredentials.SaveRequest{CA: acmecacredentials.CAZeroSSL, ExpectedRevision: 1, Clear: true, RequestID: "r4"})
	if err != nil || cleared.Configured {
		t.Fatalf("clear = %+v, %v", cleared, err)
	}
}
