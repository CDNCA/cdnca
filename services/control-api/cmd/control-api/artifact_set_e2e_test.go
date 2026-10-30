package main

// Control half of tests/artifact-set-e2e/run.sh (PA-01): the production node artifact set distributor
// (artifactsetdist) reading the production artifactsync local artifact store, edge command outbox -> NATS, NATS -> edgestatus projection (receipt recording), the
// ControlInternal service with the production artifact store over mTLS, and the IP library publication gate,
// against a real PostgreSQL schema and JetStream. The agent-gateway process (separate) delivers the commands and
// artifacts to the edge-agent process (separate), which runs the production artifact set runtime. Only node
// identity is a stand-in (no enrollment): it authorizes the gateway's node and records its session capabilities
// the way nodeidentity does.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	ipintel "github.com/cdnca/cdnca/libs/entitlement/ipintel"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

// artifactSetPKIFixture is written by the gateway half: the control server certificate and the CA that issued the
// gateway's control client certificate.
type artifactSetPKIFixture struct {
	CAFile                string `json:"ca_file"`
	ServerCertificateFile string `json:"server_certificate_file"`
	ServerPrivateKeyFile  string `json:"server_private_key_file"`
	GatewayWorkloadURI    string `json:"gateway_workload_uri"`
	NodeID                string `json:"node_id"`
	ArtifactKeyID         string `json:"artifact_key_id"`
}

type artifactSetAgentState struct {
	ActiveRevision uint64 `json:"active_revision"`
	IPIntelReady   bool   `json:"ip_intel_ready"`
	LibraryVersion uint64 `json:"library_revision"`
	// The installed engine module (wafengine.Manager.Installed; "" none).
	EngineArtifactID string `json:"engine_artifact_id"`
	EngineVersion    string `json:"engine_version"`
}

// stubNodeIdentity authorizes one node and records the session capabilities the gateway reports, exactly the
// columns nodeidentity.persistSessionCapabilities writes (no enrollment chain in this harness).
type stubNodeIdentity struct {
	pool          *pgxpool.Pool
	nodeID        uuid.UUID
	tenantID      uuid.UUID
	artifactKeyID string
	// telemetrySites (tests/telemetry-e2e): the snapshot carries the node's telemetry sites as nodeidentity
	// computes them, under the control installation ID (installationID).
	telemetrySites func(context.Context, time.Time) ([]nodeidentity.TelemetrySiteScope, error)
	installationID string
}

func (stubNodeIdentity) Authorize(context.Context, nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error) {
	return nodeidentity.Authorization{}, nodeidentity.ErrNodeStateDenied
}
func (stubNodeIdentity) Complete(context.Context, nodeidentity.CompleteRequest) (nodeidentity.EnrollmentCompletion, error) {
	return nodeidentity.EnrollmentCompletion{}, nodeidentity.ErrNodeStateDenied
}
func (stubNodeIdentity) Renew(context.Context, nodeidentity.RenewRequest) (nodeidentity.Certificate, error) {
	return nodeidentity.Certificate{}, nodeidentity.ErrNodeStateDenied
}

func (identity stubNodeIdentity) GetAuthorization(ctx context.Context, request nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
	if request.NodeID != identity.nodeID {
		return nodeidentity.AuthorizationSnapshot{}, nodeidentity.ErrNodeStateDenied
	}
	now := time.Now().UTC()
	snapshot := nodeidentity.AuthorizationSnapshot{NodeID: identity.nodeID, InstallationID: "artifact-set-e2e",
		TenantID: identity.tenantID, AuthorizationRevision: 1, AdministrativeState: "active", ConnectionAllowed: true,
		DeploymentsAllowed: true, CertificateExpirationTime: now.Add(2 * time.Hour),
		AcceptedProtocolVersions: &commonv1.ProtocolVersionRange{Minimum: &commonv1.ProtocolVersion{Major: 1},
			Maximum: &commonv1.ProtocolVersion{Major: 1}},
		SnapshotExpirationTime: now.Add(time.Hour), ArtifactEncryptionKeyID: identity.artifactKeyID}
	if identity.telemetrySites != nil {
		sites, err := identity.telemetrySites(ctx, now)
		if err != nil {
			return nodeidentity.AuthorizationSnapshot{}, err
		}
		snapshot.InstallationID, snapshot.TelemetrySites = identity.installationID, sites
	}
	facts := request.SessionFacts
	if facts == nil {
		return snapshot, nil
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(facts)
	if err != nil {
		return nodeidentity.AuthorizationSnapshot{}, err
	}
	capabilities, err := proto.MarshalOptions{Deterministic: true}.Marshal(facts.Capabilities)
	if err != nil {
		return nodeidentity.AuthorizationSnapshot{}, err
	}
	digest, capabilityDigest := sha256.Sum256(encoded), sha256.Sum256(capabilities)
	err = pgx.BeginFunc(ctx, identity.pool, func(tx pgx.Tx) error {
		// The certificate row nodeidentity joins does not exist without enrollment.
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
			artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
			facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (node_id,session_epoch) DO NOTHING`,
			identity.nodeID, int64(facts.SessionEpoch), uuid.New(), facts.CertificateSha256, facts.ArtifactEncryptionKeyId,
			facts.SelectedProtocolVersion.GetMajor(), facts.SelectedProtocolVersion.GetMinor(), capabilities,
			capabilityDigest[:], encoded, digest[:], request.GatewayWorkloadIdentity, request.GatewayInstanceID, now)
		return err
	})
	if err != nil {
		return nodeidentity.AuthorizationSnapshot{}, err
	}
	snapshot.SessionFactsSHA256 = digest[:]
	return snapshot, nil
}

// e2eLibrary is a format v2 library whose only fact is a prefix tagged carrier, as artifactsync stores the
// license catalog entry ipintel/base and its bytes after VerifyIPIntel (version = build ID).
func e2eLibrary(t *testing.T, revision uint64) (artifactcatalog.Entry, []byte) {
	t.Helper()
	generated := time.Now().UTC().Truncate(time.Second)
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: revision, BuildID: fmt.Sprintf("artifact-set-e2e-%04d", revision),
		GeneratedAt: generated, DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
		Sources: []ipintel.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
		Facts: []ipintel.Fact{{Prefix: netip.MustParsePrefix(fmt.Sprintf("1.0.%d.0/24", revision)), Tags: ipintel.TagCNTelecom,
			Country: "CN"}}})
	if err != nil {
		t.Fatal(err)
	}
	release, err := ipintel.NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := artifactcatalog.IPIntelEntry(release)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifactcatalog.VerifyIPIntel(entry, artifact.Bytes); err != nil {
		t.Fatal(err)
	}
	return entry, artifact.Bytes
}

type edgeKeySigner struct {
	keyID   string
	private ed25519.PrivateKey
}

func (signer edgeKeySigner) KeyID() string { return signer.keyID }
func (signer edgeKeySigner) PublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer edgeKeySigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestArtifactSetControlProcess(t *testing.T) {
	directory, natsURL := os.Getenv("ARTIFACT_SET_E2E_DIR"), os.Getenv("ARTIFACT_SET_E2E_NATS_URL")
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if directory == "" || natsURL == "" || databaseURL == "" {
		t.Skip("ARTIFACT_SET_E2E_DIR, ARTIFACT_SET_E2E_NATS_URL and TEST_DATABASE_URL are required; run tests/artifact-set-e2e/run.sh")
	}
	ctx := t.Context()
	var pki artifactSetPKIFixture
	waitJSONFile(t, filepath.Join(directory, "pki.json"), &pki)
	nodeID := uuid.MustParse(pki.NodeID)
	pool, tenantID, _ := controlE2EDatabase(t, databaseURL)
	seedArtifactSetNode(t, pool, tenantID, nodeID)

	// JetStream resources the control plane and the gateway share (deploy/nats bootstrap shape).
	connection, err := nats.Connect(natsURL, nats.Name("cdnca-artifact-set-e2e-control"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*nats.StreamConfig{
		{Name: "AGENT_COMMANDS", Subjects: []string{"cdnca.agent.commands.>"}, Retention: nats.WorkQueuePolicy,
			Storage: nats.FileStorage, Duplicates: time.Minute},
		{Name: edgestatus.DefaultStatusStream, Subjects: []string{edgestatus.DefaultSubjectPrefix + ".>"},
			Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Duplicates: time.Minute},
		{Name: "AGENT_HEARTBEATS", Subjects: []string{"cdnca.agent.heartbeats.>"}, Retention: nats.LimitsPolicy,
			Storage: nats.FileStorage, MaxAge: time.Hour},
	} {
		if _, err := js.AddStream(stream); err != nil {
			t.Fatal(err)
		}
	}
	statusConfig := edgestatus.DefaultNATSConsumerConfig()
	statusConfig.FetchTimeout, statusConfig.NakDelay = time.Second, 100*time.Millisecond
	if _, err := js.AddConsumer(statusConfig.Stream, &nats.ConsumerConfig{Durable: statusConfig.Durable,
		FilterSubjects: []string{statusConfig.SubjectPrefix + ".*", statusConfig.SubjectPrefix + ".generic-v2.*.*"},
		DeliverPolicy:  nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: statusConfig.AckWait,
		MaxDeliver: -1, ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: statusConfig.MaxAckPending,
		MaxWaiting: statusConfig.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: statusConfig.FetchTimeout}); err != nil {
		t.Fatal(err)
	}
	outboxConfig := edgeoutbox.DefaultConfig()
	outboxConfig.PollInterval = 100 * time.Millisecond
	publisher, err := edgeoutbox.New(pool, connection, outboxConfig)
	if err != nil {
		t.Fatal(err)
	}
	statusRuntime, err := edgestatus.NewRuntime(pool, connection, statusConfig, edgestatus.DefaultValidatorConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopRuntime := context.WithCancel(ctx)
	defer stopRuntime()
	for _, worker := range []runtimeWorker{publisher, statusRuntime} {
		go func() {
			if err := worker.Run(runCtx); err != nil && runCtx.Err() == nil {
				t.Errorf("control worker stopped: %v", err)
			}
		}()
	}
	serveControlInternal(t, runCtx, directory, pki, pool, nodeID, tenantID)

	_, private, _ := ed25519.GenerateKey(rand.Reader)
	trustFile := writeArtifactSetTrustFile(t, directory, private.Public().(ed25519.PublicKey))
	deployments, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	// The production local artifact store; a control-side ruleset next to the library must stay off the node.
	artifactsynctest.SeedDownloaded(t, pool, artifactcatalog.Entry{ArtifactID: "ruleset/e2e-rules", Kind: artifactcatalog.KindRuleset,
		Version: "1", Revision: 1, SHA256: artifactset.Digest([]byte("{}")), MediaType: artifactcatalog.MediaTypeRuleset}, []byte("{}"))
	distributor, err := artifactsetdist.New(artifactsetdist.Config{Pool: pool, Deployments: deployments,
		Source: artifactsync.NewStore(pool, time.Now),
		Signer: edgeKeySigner{keyID: e2eEdgeKeyID, private: private}, RetryAfter: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	writeE2EJSON(t, directory, "control.json", map[string]string{"trust_file": trustFile,
		"control_address": controlInternalAddress(directory)})
	var agent struct {
		StateURL string `json:"state_url"`
	}
	waitJSONFile(t, filepath.Join(directory, "agent.json"), &agent)
	defer func() {
		_, _ = http.Post(agent.StateURL+"/done", "text/plain", nil)
		_ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600)
	}()

	flow := artifactSetFlow{t: t, pool: pool, nodeID: nodeID, distributor: distributor, stateURL: agent.StateURL}
	flow.run()
}

func seedArtifactSetNode(t *testing.T, pool *pgxpool.Pool, tenantID, nodeID uuid.UUID) {
	t.Helper()
	var userID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM users ORDER BY created_at LIMIT 1`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`,
			[]any{uuid.New()}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'artifact-set-e2e','active',$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, []any{nodeID, tenantID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func controlInternalAddress(directory string) string {
	encoded, _ := os.ReadFile(filepath.Join(directory, "control-address"))
	return strings.TrimSpace(string(encoded))
}

// serveControlInternal runs the production ControlInternal service (production artifact store) over mTLS for the
// gateway workload identity.
func serveControlInternal(t *testing.T, ctx context.Context, directory string, pki artifactSetPKIFixture,
	pool *pgxpool.Pool, nodeID, tenantID uuid.UUID) {
	t.Helper()
	serveControlInternalWith(t, ctx, directory, pki, stubNodeIdentity{pool: pool, nodeID: nodeID, tenantID: tenantID,
		artifactKeyID: pki.ArtifactKeyID})
}

func serveControlInternalWith(t *testing.T, ctx context.Context, directory string, pki artifactSetPKIFixture, identity stubNodeIdentity) {
	t.Helper()
	artifacts, err := edgeartifact.NewStore(identity.pool, edgeartifact.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	service, err := controlinternal.NewService(identity, artifacts, controlinternal.Config{GatewayWorkloadURISAN: pki.GatewayWorkloadURI})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(pki.ServerCertificateFile, pki.ServerPrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(pki.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("control harness: unreadable CA")
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate},
		ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})),
		grpc.MaxRecvMsgSize(8<<20), grpc.MaxSendMsgSize(8<<20))
	controlv1.RegisterControlInternalServiceServer(server, service)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	go func() {
		<-ctx.Done()
		server.Stop()
	}()
	if err := os.WriteFile(filepath.Join(directory, "control-address"), []byte(listener.Addr().String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeE2EJSON(t *testing.T, directory, name string, value any) {
	t.Helper()
	encoded, _ := json.Marshal(value)
	if err := os.WriteFile(filepath.Join(directory, name+".tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, name+".tmp"), filepath.Join(directory, name)); err != nil {
		t.Fatal(err)
	}
}

// writeArtifactSetTrustFile writes the edge-agent trust file naming the edge publication key (same shape and mode
// as /etc/cdnca-edge-agent/trust: owner-only and read-only).
func writeArtifactSetTrustFile(t *testing.T, directory string, public ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(map[string]any{"version": 1, "keys": []map[string]string{{"key_id": e2eEdgeKeyID,
		"public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}}})
	path := filepath.Join(directory, "edge-trust.json")
	if err := os.WriteFile(path, document, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}
