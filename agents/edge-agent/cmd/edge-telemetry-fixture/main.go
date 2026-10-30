package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	preflightArgument = "--preflight-eventspool-mtls"
	maximumWireBytes  = 4 << 20
)

type fixtureConfig struct {
	nodeID, tenantID, siteID, installationID, subscriptionID  string
	domain, spoolDirectory, gatewayAddress, gatewayServerName string
	rootCAFile, clientCertificateFile, clientPrivateKeyFile   string
	eventID                                                   string
	listenPort                                                uint
	connections, sourceWatermark                              uint64
	timeout                                                   time.Duration
}

type fixtureReceipt struct {
	Status                      string `json:"status"`
	Transport                   string `json:"transport"`
	SequenceKind                string `json:"sequence_kind"`
	EventID                     string `json:"event_id"`
	NodeID                      string `json:"node_id"`
	TenantID                    string `json:"tenant_id"`
	InstallationID              string `json:"installation_id"`
	SiteID                      string `json:"site_id"`
	PackageSubscriptionID       string `json:"package_subscription_id"`
	Domain                      string `json:"domain"`
	ListenPort                  uint32 `json:"listen_port"`
	SourceWatermark             uint64 `json:"source_watermark"`
	AcknowledgedSourceWatermark uint64 `json:"acknowledged_source_watermark"`
}

type dependencies struct {
	now       func() time.Time
	publisher func(fixtureConfig, *eventspool.Spool) (eventspool.Publisher, error)
}

func main() {
	code := execute(os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr, dependencies{
		now: time.Now, publisher: newMTLSPublisher,
	})
	if code != 0 {
		os.Exit(code)
	}
}

func execute(
	args []string,
	lookupEnv func(string) (string, bool),
	stdout, stderr io.Writer,
	deps dependencies,
) int {
	if len(args) == 1 && args[0] == preflightArgument {
		_, _ = io.WriteString(stdout, "{\"capability\":\"eventspool_mtls\",\"status\":\"ready\"}\n")
		return 0
	}
	config, err := parseConfig(args, lookupEnv)
	if err != nil {
		_, _ = io.WriteString(stderr, "EDGE_TELEMETRY_FIXTURE_ERROR code=INVALID_INPUT\n")
		return 2
	}
	if deps.now == nil || deps.publisher == nil {
		_, _ = io.WriteString(stderr, "EDGE_TELEMETRY_FIXTURE_ERROR code=DEPENDENCY_UNAVAILABLE\n")
		return 1
	}
	receipt, err := runFixture(context.Background(), config, deps)
	if err != nil {
		_, _ = io.WriteString(stderr, "EDGE_TELEMETRY_FIXTURE_ERROR code=DELIVERY_FAILED\n")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(receipt); err != nil {
		_, _ = io.WriteString(stderr, "EDGE_TELEMETRY_FIXTURE_ERROR code=OUTPUT_FAILED\n")
		return 1
	}
	return 0
}

func parseConfig(args []string, lookupEnv func(string) (string, bool)) (fixtureConfig, error) {
	env := func(name string) string {
		if lookupEnv == nil {
			return ""
		}
		value, _ := lookupEnv(name)
		return value
	}
	config := fixtureConfig{}
	flags := flag.NewFlagSet("edge-telemetry-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.nodeID, "node-id", env("CDNCA_OBS_FIXTURE_NODE_ID"), "")
	flags.StringVar(&config.tenantID, "tenant-id", env("CDNCA_OBS_FIXTURE_TENANT_ID"), "")
	flags.StringVar(&config.siteID, "site-id", env("CDNCA_OBS_FIXTURE_SITE_ID"), "")
	flags.StringVar(&config.installationID, "installation-id", env("CDNCA_OBS_FIXTURE_INSTALLATION_ID"), "")
	flags.StringVar(&config.subscriptionID, "package-subscription-id", env("CDNCA_OBS_FIXTURE_PACKAGE_SUBSCRIPTION_ID"), "")
	flags.StringVar(&config.domain, "domain", env("CDNCA_OBS_FIXTURE_DOMAIN"), "")
	flags.StringVar(&config.spoolDirectory, "spool-directory", env("CDNCA_OBS_FIXTURE_SPOOL_DIRECTORY"), "")
	flags.StringVar(&config.gatewayAddress, "gateway-address", env("CDNCA_OBS_FIXTURE_GATEWAY_ADDRESS"), "")
	flags.StringVar(&config.gatewayServerName, "gateway-server-name", env("CDNCA_OBS_FIXTURE_GATEWAY_SERVER_NAME"), "")
	flags.StringVar(&config.rootCAFile, "gateway-ca-file", env("CDNCA_OBS_FIXTURE_GATEWAY_CA_FILE"), "")
	flags.StringVar(&config.clientCertificateFile, "client-certificate-file", env("CDNCA_OBS_FIXTURE_CLIENT_CERTIFICATE_FILE"), "")
	flags.StringVar(&config.clientPrivateKeyFile, "client-private-key-file", env("CDNCA_OBS_FIXTURE_CLIENT_PRIVATE_KEY_FILE"), "")
	flags.StringVar(&config.eventID, "event-id", env("CDNCA_OBS_FIXTURE_EVENT_ID"), "")
	flags.UintVar(&config.listenPort, "listen-port", parseEnvUint(env("CDNCA_OBS_FIXTURE_LISTEN_PORT")), "")
	flags.Uint64Var(&config.connections, "connections", parseEnvUint64(env("CDNCA_OBS_FIXTURE_CONNECTIONS")), "")
	flags.Uint64Var(&config.sourceWatermark, "source-watermark", parseEnvUint64(env("CDNCA_OBS_FIXTURE_SOURCE_WATERMARK")), "")
	flags.DurationVar(&config.timeout, "timeout", parseEnvDuration(env("CDNCA_OBS_FIXTURE_TIMEOUT")), "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return fixtureConfig{}, errors.New("invalid arguments")
	}
	if config.eventID == "" {
		config.eventID = uuid.NewString()
	}
	if config.connections == 0 {
		config.connections = 1
	}
	if config.sourceWatermark == 0 {
		config.sourceWatermark = 1
	}
	if config.timeout == 0 {
		config.timeout = 20 * time.Second
	}
	if !canonicalUUID(config.nodeID) || !canonicalUUID(config.tenantID) || !canonicalUUID(config.siteID) ||
		!canonicalUUID(config.installationID) || !canonicalUUID(config.subscriptionID) ||
		!validEventID(config.eventID) || !validDomain(config.domain) || config.listenPort == 0 || config.listenPort > 65535 ||
		config.connections == 0 || config.sourceWatermark == 0 || config.timeout <= 0 || config.timeout > 2*time.Minute ||
		!absoluteClean(config.spoolDirectory) || !absoluteClean(config.rootCAFile) ||
		!absoluteClean(config.clientCertificateFile) || !absoluteClean(config.clientPrivateKeyFile) ||
		config.gatewayAddress == "" || strings.TrimSpace(config.gatewayAddress) != config.gatewayAddress ||
		config.gatewayServerName == "" || strings.TrimSpace(config.gatewayServerName) != config.gatewayServerName {
		return fixtureConfig{}, errors.New("incomplete fixture configuration")
	}
	return config, nil
}

func runFixture(ctx context.Context, config fixtureConfig, deps dependencies) (fixtureReceipt, error) {
	if err := os.MkdirAll(config.spoolDirectory, 0o700); err != nil {
		return fixtureReceipt{}, err
	}
	resolvedSpool, err := filepath.EvalSymlinks(config.spoolDirectory)
	if err != nil || !absoluteClean(resolvedSpool) {
		return fixtureReceipt{}, errors.New("unsafe spool directory")
	}
	config.spoolDirectory = resolvedSpool
	now := deps.now().UTC().Add(-time.Second)
	envelope, err := connectionsEnvelope(config, now)
	if err != nil {
		return fixtureReceipt{}, err
	}
	spool, err := eventspool.New(eventspool.Config{
		Root: config.spoolDirectory, MaxEventBytes: 2048, MaxSegmentBytes: 4096,
		SoftLimitBytes: 32 << 10, HardLimitBytes: 64 << 10, MaxTenantBytes: 48 << 10,
		MaxBatchEvents: 1000, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: deps.now,
	})
	if err != nil {
		return fixtureReceipt{}, err
	}
	appended, err := spool.AppendConnections(ctx, envelope)
	if err != nil || appended.Duplicate || appended.EventID != config.eventID || appended.SourceWatermark != config.sourceWatermark {
		return fixtureReceipt{}, errors.New("append connections fixture")
	}
	publisher, err := deps.publisher(config, spool)
	if err != nil {
		return fixtureReceipt{}, err
	}
	worker, err := telemetryclient.NewWorker(telemetryclient.WorkerConfig{
		MaximumEvents: 1, EmptyInterval: 10 * time.Millisecond,
		InitialBackoff: 25 * time.Millisecond, MaximumBackoff: 250 * time.Millisecond,
	}, spool, publisher)
	if err != nil {
		return fixtureReceipt{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.RunConnections(callCtx) }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case runErr := <-done:
			return fixtureReceipt{}, runErr
		case <-callCtx.Done():
			return fixtureReceipt{}, callCtx.Err()
		case <-ticker.C:
			snapshot := worker.Snapshot()
			if snapshot.AcceptedSequence != config.sourceWatermark || snapshot.Degraded {
				continue
			}
			cancel()
			runErr := <-done
			if runErr != nil && !errors.Is(runErr, context.Canceled) {
				return fixtureReceipt{}, runErr
			}
			return fixtureReceipt{
				Status: "acknowledged", Transport: "eventspool_mtls", SequenceKind: "source_watermark",
				EventID: config.eventID, NodeID: config.nodeID, TenantID: config.tenantID,
				InstallationID: config.installationID, SiteID: config.siteID,
				PackageSubscriptionID: config.subscriptionID, Domain: config.domain,
				ListenPort: uint32(config.listenPort), SourceWatermark: config.sourceWatermark,
				AcknowledgedSourceWatermark: snapshot.AcceptedSequence,
			}, nil
		}
	}
}

func newMTLSPublisher(config fixtureConfig, spool *eventspool.Spool) (eventspool.Publisher, error) {
	dialer, err := telemetryclient.NewMTLSDialer(telemetryclient.MTLSDialerConfig{
		Address: config.gatewayAddress, ServerName: config.gatewayServerName,
		RootCAFile: config.rootCAFile, ClientCertificateFile: config.clientCertificateFile,
		ClientPrivateKeyFile: config.clientPrivateKeyFile,
		MaximumReceiveBytes:  maximumWireBytes, MaximumSendBytes: maximumWireBytes,
	})
	if err != nil {
		return nil, err
	}
	clientConfig := telemetryclient.DefaultConfig()
	clientConfig.NodeID = config.nodeID
	clientConfig.BootID = uuid.NewString()
	clientConfig.Cursor = telemetryclient.NewDurableCursor(spool)
	client, err := telemetryclient.New(clientConfig, dialer)
	if err != nil {
		return nil, err
	}
	return telemetryclient.NewPublisher(config.nodeID, client)
}

func connectionsEnvelope(config fixtureConfig, occurred time.Time) (*agentv1.ConnectionsMetricEnvelopeV1, error) {
	envelope := &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event: &commonv1.EventMetadata{
			EventId: config.eventID, OccurredTime: timestamppb.New(occurred),
		},
		TenantId: config.tenantID, InstallationId: config.installationID,
		SiteId: config.siteID, PackageSubscriptionId: config.subscriptionID,
		Connections:      config.connections,
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(occurred), SourceWatermark: config.sourceWatermark,
		NodeId: config.nodeID, Domain: config.domain, ListenPort: uint32(config.listenPort),
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	canonicalDigest := sha256.Sum256(append([]byte("cdnca.connections.canonical.v1\x00"), canonical...))
	evidenceDigest := sha256.Sum256(append([]byte("cdnca.connections.fixture-evidence.v1\x00"), canonical...))
	envelope.CanonicalEventSha256 = canonicalDigest[:]
	envelope.EvidenceSha256 = evidenceDigest[:]
	return envelope, nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validEventID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

func validDomain(value string) bool {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return len(labels) >= 2
}

func absoluteClean(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func parseEnvUint(value string) uint {
	parsed, _ := strconv.ParseUint(value, 10, 16)
	return uint(parsed)
}

func parseEnvUint64(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}

func parseEnvDuration(value string) time.Duration {
	parsed, _ := time.ParseDuration(value)
	return parsed
}
