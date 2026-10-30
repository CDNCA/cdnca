package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const (
	testNodeID         = "30000000-0000-4000-8a00-000000000001"
	testTenantID       = "10000000-0000-4000-8000-000000000001"
	testSiteID         = "20000000-0000-4000-8000-000000000001"
	testInstallationID = "70000000-0000-4000-8000-000000000002"
	testSubscriptionID = "50000000-0000-4000-8000-000000000001"
)

func TestFixtureAppendsThroughWorkerAndReportsAcknowledgement(t *testing.T) {
	spoolDirectory := t.TempDir()
	if err := os.Chmod(spoolDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher := &capturePublisher{}
	var stdout, stderr bytes.Buffer
	code := execute(fixtureArgs(spoolDirectory), nil, &stdout, &stderr, dependencies{
		now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		publisher: func(config fixtureConfig, spool *eventspool.Spool) (eventspool.Publisher, error) {
			if config.nodeID != testNodeID || spool == nil {
				t.Fatal("publisher did not receive trusted fixture identity and spool")
			}
			return publisher, nil
		},
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("execute() code=%d stderr=%q", code, stderr.String())
	}
	if len(publisher.publications) != 1 || publisher.publications[0].Subject != "cdnca.connections.v1."+testInstallationID {
		t.Fatalf("publications = %+v", publisher.publications)
	}
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(publisher.publications[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.GetNodeId() != testNodeID || envelope.GetTenantId() != testTenantID ||
		envelope.GetSiteId() != testSiteID || envelope.GetInstallationId() != testInstallationID ||
		envelope.GetPackageSubscriptionId() != testSubscriptionID || envelope.GetDomain() != "obs.example.test" ||
		envelope.GetListenPort() != 443 || envelope.GetSourceWatermark() != 41 ||
		len(envelope.GetCanonicalEventSha256()) != 32 || len(envelope.GetEvidenceSha256()) != 32 {
		t.Fatalf("connections envelope = %+v", &envelope)
	}
	var receipt fixtureReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "acknowledged" || receipt.Transport != "eventspool_mtls" ||
		receipt.SequenceKind != "source_watermark" || receipt.EventID != "fixture-event-1" ||
		receipt.SourceWatermark != 41 || receipt.AcknowledgedSourceWatermark != 41 {
		t.Fatalf("receipt = %+v", receipt)
	}

	resolvedSpool, err := filepath.EvalSymlinks(spoolDirectory)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := eventspool.New(fixtureSpoolConfig(resolvedSpool))
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.FlushConnections(context.Background(), &capturePublisher{}, 1)
	if err != nil || result.Published != 0 {
		t.Fatalf("acknowledged spool retained pending record: %+v, %v", result, err)
	}
}

func TestFixtureFailsClosedWithoutRequiredInputsAndDoesNotLeakPaths(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "private-key-secret-sentinel")
	var stdout, stderr bytes.Buffer
	code := execute([]string{"--client-private-key-file", secret}, nil, &stdout, &stderr, dependencies{})
	combined := stdout.String() + stderr.String()
	if code != 2 || !strings.Contains(combined, "INVALID_INPUT") || strings.Contains(combined, secret) {
		t.Fatalf("invalid input code=%d output=%q", code, combined)
	}
}

func TestFixturePreflightRequiresExactArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{preflightArgument}, nil, &stdout, &stderr, dependencies{}); code != 0 ||
		stdout.String() != "{\"capability\":\"eventspool_mtls\",\"status\":\"ready\"}\n" || stderr.Len() != 0 {
		t.Fatalf("preflight code/output = %d, %q, %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := execute([]string{preflightArgument, "extra"}, nil, &stdout, &stderr, dependencies{}); code != 2 {
		t.Fatalf("non-exact preflight code = %d", code)
	}
}

func fixtureArgs(spoolDirectory string) []string {
	return []string{
		"--node-id", testNodeID,
		"--tenant-id", testTenantID,
		"--site-id", testSiteID,
		"--installation-id", testInstallationID,
		"--package-subscription-id", testSubscriptionID,
		"--domain", "obs.example.test",
		"--listen-port", "443",
		"--spool-directory", spoolDirectory,
		"--gateway-address", "127.0.0.1:9443",
		"--gateway-server-name", "localhost",
		"--gateway-ca-file", filepath.Join(spoolDirectory, "ca.crt"),
		"--client-certificate-file", filepath.Join(spoolDirectory, "client.crt"),
		"--client-private-key-file", filepath.Join(spoolDirectory, "client.key"),
		"--event-id", "fixture-event-1",
		"--connections", "7",
		"--source-watermark", "41",
		"--timeout", "2s",
	}
}

func fixtureSpoolConfig(root string) eventspool.Config {
	return eventspool.Config{
		Root: root, MaxEventBytes: 2048, MaxSegmentBytes: 4096,
		SoftLimitBytes: 32 << 10, HardLimitBytes: 64 << 10, MaxTenantBytes: 48 << 10,
		MaxBatchEvents: 1000, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

type capturePublisher struct {
	publications []eventspool.Publication
}

func (publisher *capturePublisher) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	publisher.publications = append(publisher.publications, publications...)
	return eventspool.PublishAck{Acknowledged: len(publications)}, nil
}
