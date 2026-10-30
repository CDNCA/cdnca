package certificateasset

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublicationIntentStableIdempotencyAndCappedJitter40(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	first := publicationIntentIdempotencyKey(tenantID, siteID, 7)
	if first == "" || first != publicationIntentIdempotencyKey(tenantID, siteID, 7) ||
		first == publicationIntentIdempotencyKey(tenantID, siteID, 8) {
		t.Fatalf("unstable publication idempotency key %q", first)
	}
	config := DefaultPublicationIntentStoreConfig()
	config.RetryBase = time.Second
	config.RetryMaximum = 10 * time.Second
	for _, test := range []struct {
		attempt int
		jitter  time.Duration
		want    time.Duration
	}{
		{attempt: 1, jitter: 250 * time.Millisecond, want: 1250 * time.Millisecond},
		{attempt: 4, jitter: time.Second, want: 9 * time.Second},
		{attempt: 20, jitter: 5 * time.Second, want: 10 * time.Second},
	} {
		got, err := publicationIntentRetryDelay(config, test.attempt, func(max time.Duration) time.Duration {
			if test.jitter > max {
				return max
			}
			return test.jitter
		})
		if err != nil || got != test.want {
			t.Fatalf("retry delay attempt=%d got=%s err=%v want=%s", test.attempt, got, err, test.want)
		}
	}
}

func TestPublicationIntentStoreSQLContract40(t *testing.T) {
	source := publicationStoreSource40(t, "publication_store.go")
	for _, required := range []string{
		"func (store *PublicationIntentStore) ClaimPublicationIntent",
		"func (store *PublicationIntentStore) CompletePublicationIntent",
		"func (store *PublicationIntentStore) FailPublicationIntent",
		"FOR UPDATE OF intent SKIP LOCKED",
		"previous_intent.binding_revision<intent.binding_revision",
		"previous_latest.state NOT IN ('succeeded','permanent_failed')",
		"latest.state IN ('pending','retry_wait')",
		"latest.state='leased' AND latest.lease_expires_at<=transaction_timestamp()",
		"INSERT INTO certificate_publication_intent_state_facts",
		"actor_session_id", "actor_scope_kind", "actor_user_revision",
		"target_tenant_id", "target_tenant_revision",
		"publication_id", "publication_revision", "config_version_id", "rollout_id", "rollout_revision",
		"transaction_timestamp()",
		"lease_token=$2", "attempt=$3", "lease_expires_at>transaction_timestamp()",
		`"succeeded"`, `"retry_wait"`, `"permanent_failed"`,
	} {
		if !strings.Contains(compactPublicationStore40(source), compactPublicationStore40(required)) {
			t.Errorf("publication claim store missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "ciphertext", "nonce", "certificate_pem", "key_reference"} {
		if strings.Contains(strings.ToLower(source), forbidden) {
			t.Errorf("publication claim store contains private material field %q", forbidden)
		}
	}
}

func TestPublicationIntentMigration118StateMachineContract40(t *testing.T) {
	up := publicationStoreSource40(t, filepath.Join("..", "..", "migrations", "118_certificate_publication_claims.up.sql"))
	for _, required := range []string{
		"REQUIRED_117_HEAD_FROZEN_118",
		"CREATE TABLE certificate_publication_intent_state_facts",
		"PRIMARY KEY (tenant_scope_id,site_id,binding_revision,sequence)",
		"state text NOT NULL CHECK (state IN ('pending','leased','retry_wait','succeeded','permanent_failed'))",
		"idempotency_key text NOT NULL",
		"certificate_publication_intent_states_immutable_118",
		"certificate_publication_intent_states_no_truncate_118",
		"certificate_publication_intent_state_validate_118",
		"certificate_publication_intent_initialize_118",
		"pg_advisory_xact_lock",
		"NEW.occurred_at IS DISTINCT FROM transaction_timestamp()",
		"previous.state IN ('pending','retry_wait') AND NEW.state='leased'",
		"previous.state='leased' AND NEW.state='leased'",
		"previous.state='leased' AND NEW.state IN ('retry_wait','succeeded','permanent_failed')",
	} {
		if !strings.Contains(compactPublicationStore40(up), compactPublicationStore40(required)) {
			t.Errorf("publication claim migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "ciphertext", "nonce", "certificate_pem", "key_reference"} {
		if strings.Contains(strings.ToLower(up), forbidden) {
			t.Errorf("publication claim migration contains private material field %q", forbidden)
		}
	}
}

func publicationStoreSource40(t *testing.T, name string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve publication store test path")
	}
	content, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func compactPublicationStore40(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
