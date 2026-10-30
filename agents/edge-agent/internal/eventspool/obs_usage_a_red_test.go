package eventspool

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

func TestOBSUsageAPressureNeverAdvancesDurableAcknowledgement(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("pressure-base", tenantOne)}); err != nil {
		t.Fatal(err)
	}
	before, err := spool.Stats()
	if err != nil {
		t.Fatal(err)
	}

	spool.config.SoftLimitBytes = before.SegmentBytes + 1
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("pressure-soft", tenantOne)}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("soft pressure error=%v", err)
	}
	afterSoft, err := spool.Stats()
	if err != nil || afterSoft.AckedSequence != before.AckedSequence || afterSoft.PendingEvents != before.PendingEvents {
		t.Fatalf("soft pressure advanced durable state: before=%+v after=%+v err=%v", before, afterSoft, err)
	}

	spool.config.SoftLimitBytes = config.SoftLimitBytes
	spool.config.HardLimitBytes = before.SegmentBytes + 1
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("pressure-hard", tenantOne)}); !errors.Is(err, ErrHardLimit) {
		t.Fatalf("hard pressure error=%v", err)
	}
	afterHard, err := spool.Stats()
	if err != nil || afterHard.AckedSequence != before.AckedSequence || afterHard.PendingEvents != before.PendingEvents {
		t.Fatalf("hard pressure advanced durable state: before=%+v after=%+v err=%v", before, afterHard, err)
	}
}

func TestOBSUsageASecretSegmentRedactionMatrix(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.Path = "/callback?client_secret=query-secret&clientSecret=camel-secret&refreshSecret=refresh-secret&secretary=query-neighbor&secretaryId=query-id&clientSecretive=query-secretive"
	event.RequestHeaders = map[string]string{
		"X-API-Secret": "header-secret", "X-API-Secretary": "header-neighbor",
	}
	event.RequestBody = map[string]any{
		"client_secret": "body-secret", "clientSecret": "camel-body-secret", "refreshSecret": "refresh-body-secret",
		"secretary": "body-neighbor", "secretaryId": "body-id", "clientSecretive": "body-secretive",
		"nested": map[string]any{
			"client_secret": "nested-secret", "clientSecret": "nested-camel-secret", "refreshSecret": "nested-refresh-secret",
			"secretary": "nested-neighbor", "secretaryId": "nested-id", "clientSecretive": "nested-secretive",
		},
	}

	captured, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{
		RequestHeaders:    []string{"X-API-Secret", "X-API-Secretary"},
		RequestBodyFields: []string{"client_secret", "clientSecret", "refreshSecret", "secretary", "secretaryId", "clientSecretive", "nested"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.ParseRequestURI(captured.Path)
	if err != nil {
		t.Fatal(err)
	}
	nested := captured.RequestBody["nested"].(map[string]any)
	if parsed.Query().Get("client_secret") != redactedValue ||
		parsed.Query().Get("clientSecret") != redactedValue || parsed.Query().Get("refreshSecret") != redactedValue ||
		parsed.Query().Get("secretary") != "query-neighbor" || parsed.Query().Get("secretaryId") != "query-id" ||
		parsed.Query().Get("clientSecretive") != "query-secretive" ||
		captured.RequestHeaders["X-Api-Secret"] != redactedValue ||
		captured.RequestHeaders["X-Api-Secretary"] != "header-neighbor" ||
		captured.RequestBody["client_secret"] != redactedValue ||
		captured.RequestBody["clientSecret"] != redactedValue || captured.RequestBody["refreshSecret"] != redactedValue ||
		captured.RequestBody["secretary"] != "body-neighbor" || captured.RequestBody["secretaryId"] != "body-id" ||
		captured.RequestBody["clientSecretive"] != "body-secretive" || nested["client_secret"] != redactedValue ||
		nested["clientSecret"] != redactedValue || nested["refreshSecret"] != redactedValue ||
		nested["secretary"] != "nested-neighbor" || nested["secretaryId"] != "nested-id" ||
		nested["clientSecretive"] != "nested-secretive" {
		t.Fatalf("secret marker matrix was not preserved: %#v", captured)
	}
}
