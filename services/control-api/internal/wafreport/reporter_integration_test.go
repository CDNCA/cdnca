package wafreport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

type staticWAFSource []json.RawMessage

func (source staticWAFSource) ListCustomWAFForReport(context.Context) ([]json.RawMessage, error) {
	return source, nil
}

// One refused policy must not stall the sequence (a controller stuck at sequence 16 for days):
// it is left out and logged, the rest is sent and the snapshot marked sent.
func TestReporterSkipsRefusedPolicyAndSendsRestPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	installationID := uuid.New()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	var sent []json.RawMessage
	client, err := NewClient("https://license.example.test", roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Sequence   uint64            `json:"sequence"`
			ObservedAt int64             `json:"observed_at"`
			Policies   []json.RawMessage `json:"policies"`
			RequestID  string            `json:"request_id"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		sent = body.Policies
		for _, policy := range body.Policies {
			if strings.Contains(string(policy), "fb20") { // what license-service does with the whole report
				return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(`{"error":{"code":"invalid_request","message":"invalid request"}}`))}, nil
			}
		}
		snapshot := Snapshot{InstallationID: installationID, Sequence: body.Sequence, RequestID: body.RequestID,
			ObservedAt: time.Unix(body.ObservedAt, 0).UTC(), Policies: body.Policies, PoliciesDigest: DigestPolicies(body.Policies)}
		encoded := encodeReportReceipt(t, reportContractReceipt(snapshot, key))
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	reporter, err := NewReporter(Config{
		Source: staticWAFSource{json.RawMessage(blockAllPolicy), json.RawMessage(managedSitePolicy)},
		Store:  NewStore(pool, nil), Client: client, InstallationID: installationID, PrivateKey: key,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.reportOnce(t.Context()); err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(sent) != 1 || !strings.Contains(string(sent[0]), "fb17") {
		t.Fatalf("sent policies = %s", sent)
	}
	var stored int
	var sentAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_array_length(policies),sent_at FROM waf_custom_rule_report_state WHERE installation_id=$1`,
		installationID).Scan(&stored, &sentAt); err != nil || stored != 1 || sentAt == nil {
		t.Fatalf("state policies=%d sent_at=%v err=%v", stored, sentAt, err)
	}
	if !strings.Contains(logs.String(), "custom WAF policy left out of report") || !strings.Contains(logs.String(), "01a1b548-aee3-79ae-8b01-8c0c2df3fb20") {
		t.Fatalf("skip not logged: %s", logs.String())
	}
}
