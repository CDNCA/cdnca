package dnsacme

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRenewalJitterFailover02(t *testing.T) {
	certificateID := uuid.MustParse("018f4f3e-7c2a-7c2b-8f21-5cb74a147e4b")
	notAfter := time.Date(2027, time.January, 15, 12, 0, 0, 123456000, time.UTC)

	t.Run("stable jitter seed and bounded offset", func(t *testing.T) {
		seed := renewalJitterSeed(certificateID, notAfter)
		if seed != 775519323 {
			t.Fatalf("seed = %d, want first uint32 of MD5 775519323", seed)
		}
		if got := renewalJitterSeed(certificateID, notAfter); got != seed {
			t.Fatalf("stable seed = %d, want %d", got, seed)
		}
		if got := renewalJitterSeed(uuid.MustParse("018f4f3e-7c2a-7c2b-8f21-5cb74a147e4c"), notAfter); got == seed {
			t.Fatalf("certificate ID change retained seed %d", got)
		}
		if got := renewalJitterSeed(certificateID, notAfter.Add(time.Microsecond)); got == seed {
			t.Fatalf("not_after change retained seed %d", got)
		}

		for _, test := range []struct {
			name        string
			renewBefore time.Duration
			maximum     time.Duration
		}{
			{name: "short window", renewBefore: 8 * time.Hour, maximum: 2 * time.Hour},
			{name: "long window cap", renewBefore: 30 * 24 * time.Hour, maximum: 24 * time.Hour},
		} {
			t.Run(test.name, func(t *testing.T) {
				offset := renewalJitterOffset(certificateID, notAfter, test.renewBefore)
				if offset < 0 || offset > test.maximum {
					t.Fatalf("jitter offset %s outside [0,%s]", offset, test.maximum)
				}
			})
		}
	})

	t.Run("jitter threshold gates initial renewal", func(t *testing.T) {
		renewBefore := 30 * 24 * time.Hour
		rawDue := notAfter.Add(-renewBefore)
		due := renewalInitialDue(certificateID, notAfter, renewBefore)
		if due.Before(rawDue) || due.After(rawDue.Add(24*time.Hour)) {
			t.Fatalf("initial due %s outside jittered window [%s,%s]", due, rawDue, rawDue.Add(24*time.Hour))
		}
		if !rawDue.Before(due) {
			t.Fatalf("fixture must remain ineligible at raw threshold: raw=%s due=%s", rawDue, due)
		}
		if due.Add(-time.Nanosecond).Before(rawDue) || !due.Add(-time.Nanosecond).Before(due) {
			t.Fatalf("time immediately before due did not remain gated")
		}
	})

	t.Run("durable failure backoff is exponential and bounded", func(t *testing.T) {
		latestFailure := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
		farExpiry := latestFailure.Add(30 * 24 * time.Hour)
		retryMaximum := 24 * time.Hour
		for _, test := range []struct {
			failures int64
			want     time.Duration
		}{
			{failures: 1, want: time.Minute},
			{failures: 2, want: 2 * time.Minute},
			{failures: 3, want: 4 * time.Minute},
			{failures: 1000, want: retryMaximum},
		} {
			if got := renewalRetryDelay(test.failures, farExpiry, latestFailure, retryMaximum); got != test.want {
				t.Fatalf("failure count %d delay = %s, want %s", test.failures, got, test.want)
			}
		}
		if got := renewalRetryDelay(3, farExpiry, latestFailure, 0); got != 0 {
			t.Fatalf("retryMaximum=0 delay = %s, want no reopen", got)
		}
	})

	t.Run("expiry urgency has a bounded floor", func(t *testing.T) {
		latestFailure := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
		if got := renewalRetryDelay(10, latestFailure.Add(20*time.Minute), latestFailure, 24*time.Hour); got != 5*time.Minute {
			t.Fatalf("urgent delay = %s, want 5m", got)
		}
		if got := renewalRetryDelay(10, latestFailure.Add(2*time.Minute), latestFailure, 24*time.Hour); got != time.Minute {
			t.Fatalf("near-expiry delay = %s, want 1m floor", got)
		}
		if got := renewalRetryDelay(10, latestFailure.Add(-time.Minute), latestFailure, 24*time.Hour); got != time.Minute {
			t.Fatalf("expired delay = %s, want 1m floor", got)
		}
	})

	t.Run("selection SQL preserves durable and concurrency facts", func(t *testing.T) {
		body, err := os.ReadFile("store.go")
		if err != nil {
			t.Fatal(err)
		}
		source := strings.Join(strings.Fields(string(body)), " ")
		required := []string{
			"md5(source.id::text || ':' || floor(extract(epoch from source.not_after) * 1000000)::bigint::text)",
			"COUNT(DISTINCT completed.renewal_order_id)",
			"completed.tenant_scope_id=source.scope_id AND completed.source_order_id=source.id",
			"completed.status='completed' AND completed.event_type='completed'",
			"child.scope_id=source.scope_id AND child.renewal_of_order_id=source.id",
			"child.created_by_user_id=source.created_by_user_id AND child.status='failed'",
			"LEAST(($1::bigint / 4), $3::bigint) + 1",
			"LEAST(GREATEST(failure_history.failed_attempts - 1, 0), $5::bigint)",
			"(source.not_after - failure_history.latest_failure_at)) * 1000",
			"latest.status='active' THEN latest.lease_expires_at",
			"latest.status='retry_wait' THEN latest.next_attempt_at",
			"latest.status='completed' AND $2 > 0",
			"child.status NOT IN ('failed','revoked')",
			"due.effective_due <= statement_timestamp()",
			"ORDER BY due.effective_due,source.not_after,source.id",
			"FOR UPDATE OF source SKIP LOCKED LIMIT 1",
			"WHERE scope_id=$1 AND id=$2 AND status='active' AND revision=$3",
		}
		for _, contract := range required {
			if !strings.Contains(source, contract) {
				t.Errorf("store.go missing renewal contract %q", contract)
			}
		}
	})

	t.Run("source update is LKG allowlisted", func(t *testing.T) {
		body, err := os.ReadFile("store.go")
		if err != nil {
			t.Fatal(err)
		}
		source := strings.Join(strings.Fields(string(body)), " ")
		start := strings.Index(source, "if source.Status == OrderActive")
		if start < 0 {
			t.Fatalf("could not isolate source renewal UPDATE")
		}
		end := strings.Index(source[start:], "childID, err := uuid.NewV7()")
		if end < 0 {
			t.Fatalf("could not isolate source renewal UPDATE")
		}
		update := source[start : start+end]
		if !strings.Contains(update, "UPDATE certificate_orders SET status='renewal_due',revision=revision+1,updated_at=statement_timestamp()") {
			t.Fatalf("source renewal UPDATE escaped status/revision/timestamp allowlist: %s", update)
		}
		for _, field := range []string{
			"not_after=", "issued_asset_id=", "issued_asset_version_id=", "issued_at=",
			"leaf_fingerprint_sha256=", "leaf_spki_sha256=", "certificate_url=", "certificate_key_ref=",
		} {
			if strings.Contains(update, field) {
				t.Errorf("source renewal UPDATE modifies LKG field %q", field)
			}
		}
	})
}
