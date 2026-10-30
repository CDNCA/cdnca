//go:build integration

package main

// Control half of tests/cert-recovery-e2e/run.sh (ADR 0013 GW-02, expired node certificate self-recovery). Built with
// -tags integration,cdnca_e2e_short_cert_ttl and CDNCA_E2E_NODE_CERTIFICATE_TTL=2m: the production ControlInternal
// runtime (openControlInternalRuntime: real nodeidentity, node CA signer, recovery notifications) issues node
// certificates of two minutes, so they really expire under the gateway's wall-clock TLS. This process starts the
// agent-gateway half (Redis session coordinator) as a child, kills it and starts it again; the edge-agent half runs
// in the node runtime image with OpenResty and probes it all along.
//
// ① the node enrolls for real and connects; the gateway goes away until the certificate expired; when it is back the
//    node recovers the certificate with its own key (RecoverCertificate on the enrollment listener) and reconnects
//    with the new one, no operator involved: one node_certificate_recoveries row, a 'recovered' event, the expired
//    certificate retired, a session with the new certificate, ControlInternal authorizes it.
// ② a recovery signed by another key (CSR and signature of a new key around the expired certificate) is refused
//    (PermissionDenied) and writes nothing.
// ③ the node's certificate is revoked; once it expired the node's recovery is refused (PermissionDenied ->
//    ErrRecoveryRefused) and the node keeps running, retrying, without a new certificate.
// OpenResty answers 200 to every probe from start to end.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeca"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// certRecoveryAgentState is the edge-agent half's GET /state.
type certRecoveryAgentState struct {
	CertificateSHA256 string    `json:"certificate_sha256"`
	CertificateSerial string    `json:"certificate_serial"`
	NotAfter          time.Time `json:"not_after"`
	Probes            int       `json:"probes"`
	ProbeFailures     int       `json:"probe_failures"`
	LastProbeFailure  string    `json:"last_probe_failure"`
	Recovered         int       `json:"recovered"`
	RecoveryRefused   int       `json:"recovery_refused"`
	LastRecoveryError string    `json:"last_recovery_error"`
	ClientRunning     bool      `json:"client_running"`
}

func TestCertRecoveryControlProcess(t *testing.T) {
	directory, agentURL := os.Getenv("CERT_RECOVERY_E2E_DIR"), os.Getenv("CERT_RECOVERY_E2E_AGENT_URL")
	gatewayBinary, redisAddress := os.Getenv("CERT_RECOVERY_E2E_GATEWAY_BIN"), os.Getenv("CERT_RECOVERY_E2E_REDIS")
	enrollmentPort, mtlsPort := os.Getenv("CERT_RECOVERY_E2E_ENROLLMENT_PORT"), os.Getenv("CERT_RECOVERY_E2E_MTLS_PORT")
	if directory == "" || agentURL == "" || gatewayBinary == "" || redisAddress == "" || enrollmentPort == "" || mtlsPort == "" {
		t.Skip("CERT_RECOVERY_E2E_* are not set; run tests/cert-recovery-e2e/run.sh")
	}
	ttl := nodeidentity.DefaultConfig().CertificateTTL
	if ttl > 5*time.Minute {
		t.Fatalf("node certificate TTL %s: build with -tags cdnca_e2e_short_cert_ttl and set CDNCA_E2E_NODE_CERTIFICATE_TTL", ttl)
	}
	ctx := t.Context()
	pool := openControlRuntimeDatabase(t)
	pki := newControlRuntimePKI(t)
	seedControlRuntimeCAEpoch(t, pool, pki.nodeCA)
	nodeID, token := seedControlRuntimePlatformNode(t, pool)
	runtime, err := openControlInternalRuntime(ctx, config.Config{
		ControlInternalGRPCAddr: unusedControlAddress(t), ControlInternalServerCert: pki.serverCertificate,
		ControlInternalServerKey: pki.serverKey, ControlInternalGatewayCA: pki.transportCA,
		ControlInternalGatewayURI: controlinternal.DefaultGatewayWorkloadURISAN, NodeCACertificateChainFile: pki.nodeCA,
		NodeCAPrivateKeyFile: pki.nodeCAKey, ShutdownPeriod: 2 * time.Second,
	}, pool)
	if err != nil {
		t.Fatalf("openControlInternalRuntime: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	serveCtx, stopServe := context.WithCancel(ctx)
	t.Cleanup(stopServe)
	go func() { _ = runtime.Serve(serveCtx) }()
	waitControlReady(t, runtime.Ready)
	connection := dialControlRuntime(t, runtime.Address(), pki, pki.gatewayCertificate, pki.gatewayKey)
	t.Cleanup(func() { _ = connection.Close() })
	control := controlv1.NewControlInternalServiceClient(connection)
	signer, err := nodeca.LoadSignerFromFiles(pki.nodeCA, pki.nodeCAKey)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := nodeidentity.NewService(nodeidentity.NewStore(pool), signer, nodeidentity.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	writeE2EJSON(t, directory, "gateway-config.json", map[string]string{"control_address": runtime.Address(),
		"server_certificate_file": pki.serverCertificate, "server_private_key_file": pki.serverKey,
		"transport_ca_file": pki.transportCA, "node_ca_file": pki.nodeCA,
		"gateway_certificate_file": pki.gatewayCertificate, "gateway_private_key_file": pki.gatewayKey,
		"redis_address": redisAddress, "enrollment_listen": "0.0.0.0:" + enrollmentPort, "mtls_listen": "0.0.0.0:" + mtlsPort})
	gateway := &certRecoveryGateway{t: t, binary: gatewayBinary, directory: directory, address: "127.0.0.1:" + mtlsPort}
	t.Cleanup(gateway.stop)
	gateway.start()

	transportCA, err := os.ReadFile(pki.transportCA)
	if err != nil {
		t.Fatal(err)
	}
	rootCAFile := filepath.Join(directory, "gateway-root-ca.pem")
	if err := os.WriteFile(rootCAFile, transportCA, 0o644); err != nil {
		t.Fatal(err)
	}
	trustKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeE2EJSON(t, directory, "gateway.json", map[string]string{"enrollment_port": enrollmentPort, "mtls_port": mtlsPort,
		"server_name": "localhost", "root_ca_file": rootCAFile, "enrollment_token": token, "node_id": nodeID.String(),
		"trust_file": writeArtifactSetTrustFile(t, directory, trustKey)})
	var ready struct {
		Ready bool `json:"ready"`
	}
	waitJSONFile(t, filepath.Join(directory, "agent.json"), &ready)
	defer func() {
		_, _ = http.Post(agentURL+"/done", "text/plain", nil)
		_ = os.WriteFile(filepath.Join(directory, "finished"), nil, 0o600)
	}()
	flow := certRecoveryFlow{t: t, pool: pool, nodeID: nodeID, agentURL: agentURL, control: control}

	// ① expired while the gateway is away -> recovered with the node's own key.
	first := flow.agent()
	if first.NotAfter.Sub(time.Now()) > ttl+time.Minute {
		t.Fatalf("enrolled certificate expires %s, want within the %s test TTL", first.NotAfter, ttl)
	}
	firstEpoch := flow.waitSession(first.CertificateSHA256, 0, time.Minute)
	t.Logf("node %s enrolled and connected: certificate %s (expires %s), session epoch %d",
		nodeID, first.CertificateSerial, first.NotAfter.Format(time.RFC3339), firstEpoch)
	gateway.stop()
	t.Logf("gateway stopped; waiting for the certificate to expire at %s", first.NotAfter.Format(time.RFC3339))
	time.Sleep(time.Until(first.NotAfter) + 3*time.Second)
	if state := flow.agent(); state.CertificateSHA256 != first.CertificateSHA256 {
		t.Fatalf("certificate changed while the gateway was away: %+v", state)
	}
	gateway.start()
	recovered := flow.waitAgent("certificate recovered", 3*time.Minute, func(state certRecoveryAgentState) bool {
		return state.CertificateSHA256 != first.CertificateSHA256 && state.Recovered == 1
	})
	recoveredEpoch := flow.waitSession(recovered.CertificateSHA256, firstEpoch, time.Minute)
	expiredID := flow.certificateID(first.CertificateSerial)
	issuedID := flow.certificateID(recovered.CertificateSerial)
	if got := flow.count(`SELECT count(*) FROM node_certificate_recoveries WHERE node_id=$1 AND expired_certificate_id=$2
		AND issued_certificate_id=$3`, nodeID, expiredID, issuedID); got != 1 {
		t.Fatalf("node_certificate_recoveries for %s -> %s: %d rows", expiredID, issuedID, got)
	}
	if got := flow.count(`SELECT count(*) FROM node_certificate_events WHERE node_id=$1 AND event_type='recovered'
		AND certificate_id=$2 AND related_certificate_id=$3`, nodeID, issuedID, expiredID); got != 1 {
		t.Fatalf("'recovered' certificate events: %d", got)
	}
	var rotation string
	if err := pool.QueryRow(ctx, `SELECT rotation_status FROM node_certificates WHERE id=$1`, expiredID).Scan(&rotation); err != nil || rotation != "retired" {
		t.Fatalf("expired certificate rotation_status %q (%v), want retired", rotation, err)
	}
	flow.expectAuthorized(recovered)
	t.Logf("PASS ① certificate expired with the gateway away, recovered with the node key after it came back: "+
		"%s -> %s, session epoch %d -> %d, ControlInternal authorizes the new certificate", first.CertificateSerial,
		recovered.CertificateSerial, firstEpoch, recoveredEpoch)

	// ② another key around the expired certificate.
	flow.expectOtherKeyRefused(first.CertificateSerial)
	t.Log("PASS ② recovery signed with another key refused (PermissionDenied), nothing written")

	// ③ revoked: recovery after expiry is refused, the node keeps running.
	gateway.stop() // no renewal from here on: the node keeps the certificate that is revoked below
	current := flow.agent()
	if err := identities.Revoke(ctx, nodeidentity.RevokeRequest{RequestID: uuid.Must(uuid.NewV7()).String(), NodeID: nodeID,
		SerialNumber: current.CertificateSerial, Reason: "cert-recovery-e2e"}); err != nil {
		t.Fatalf("revoke %s: %v", current.CertificateSerial, err)
	}
	gateway.start()
	t.Logf("certificate %s revoked; waiting for it to expire at %s", current.CertificateSerial, current.NotAfter.Format(time.RFC3339))
	time.Sleep(time.Until(current.NotAfter))
	refused := flow.waitAgent("recovery of the revoked certificate refused", 2*time.Minute, func(state certRecoveryAgentState) bool {
		return state.RecoveryRefused >= 1
	})
	if refused.CertificateSHA256 != current.CertificateSHA256 || refused.Recovered != 1 || !refused.ClientRunning ||
		!strings.Contains(refused.LastRecoveryError, "refused") {
		t.Fatalf("after the refused recovery: %+v", refused)
	}
	if got := flow.count(`SELECT count(*) FROM node_certificate_recoveries WHERE node_id=$1`, nodeID); got != 1 {
		t.Fatalf("node_certificate_recoveries after the refused recovery: %d rows", got)
	}
	t.Logf("PASS ③ revoked certificate %s: recovery refused (%s), node still running without a new certificate",
		current.CertificateSerial, refused.LastRecoveryError)

	final := flow.agent()
	if final.ProbeFailures != 0 || final.Probes < 100 {
		t.Fatalf("OpenResty probes: %d, failures %d (%s)", final.Probes, final.ProbeFailures, final.LastProbeFailure)
	}
	t.Logf("PASS OpenResty answered 200 to all %d probes while the gateway went away, the certificate expired, was recovered and refused", final.Probes)
}

// certRecoveryGateway runs the agent-gateway half as a child process; each start is a new gateway instance.
type certRecoveryGateway struct {
	t         *testing.T
	binary    string
	directory string
	address   string
	command   *exec.Cmd
	starts    int
}

func (gateway *certRecoveryGateway) start() {
	t := gateway.t
	t.Helper()
	gateway.starts++
	log, err := os.Create(filepath.Join(gateway.directory, fmt.Sprintf("gateway-%d.log", gateway.starts)))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(gateway.binary, "-test.run", "^TestCertRecoveryGatewayProcess$", "-test.count=1", "-test.v",
		"-test.timeout", "60m")
	command.Env = append(os.Environ(), "CERT_RECOVERY_E2E_DIR="+gateway.directory,
		"CERT_RECOVERY_E2E_GATEWAY_INSTANCE="+uuid.NewString())
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	gateway.command = command
	deadline := time.Now().Add(time.Minute)
	for {
		if probe, err := net.DialTimeout("tcp", gateway.address, time.Second); err == nil {
			_ = probe.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway start %d does not listen on %s", gateway.starts, gateway.address)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (gateway *certRecoveryGateway) stop() {
	if gateway.command == nil {
		return
	}
	_ = gateway.command.Process.Kill()
	_ = gateway.command.Wait()
	gateway.command = nil
}

type certRecoveryFlow struct {
	t        *testing.T
	pool     *pgxpool.Pool
	nodeID   uuid.UUID
	agentURL string
	control  controlv1.ControlInternalServiceClient
}

func (flow *certRecoveryFlow) agent() certRecoveryAgentState {
	flow.t.Helper()
	response, err := http.Get(flow.agentURL + "/state")
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	var state certRecoveryAgentState
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		flow.t.Fatal(err)
	}
	if !state.ClientRunning {
		flow.t.Fatalf("edge-agent gateway client stopped: %+v", state)
	}
	return state
}

func (flow *certRecoveryFlow) waitAgent(what string, timeout time.Duration, done func(certRecoveryAgentState) bool) certRecoveryAgentState {
	flow.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		state := flow.agent()
		if done(state) {
			return state
		}
		if time.Now().After(deadline) {
			flow.t.Fatalf("%s: not within %s: %+v", what, timeout, state)
		}
		time.Sleep(time.Second)
	}
}

// waitSession waits for a gateway session of the node with the certificate (epoch above after) and returns its epoch.
func (flow *certRecoveryFlow) waitSession(certificateSHA256 string, after int64, timeout time.Duration) int64 {
	flow.t.Helper()
	digest, err := hex.DecodeString(certificateSHA256)
	if err != nil {
		flow.t.Fatal(err)
	}
	deadline := time.Now().Add(timeout)
	for {
		var epoch int64
		if err := flow.pool.QueryRow(flow.t.Context(), `SELECT COALESCE(max(session_epoch),0) FROM node_session_capabilities
			WHERE node_id=$1 AND certificate_sha256=$2 AND session_epoch>$3`, flow.nodeID, digest, after).Scan(&epoch); err != nil {
			flow.t.Fatal(err)
		}
		if epoch > 0 {
			return epoch
		}
		if time.Now().After(deadline) {
			flow.t.Fatalf("no gateway session with certificate %s above epoch %d within %s: %+v", certificateSHA256, after, timeout, flow.agent())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (flow *certRecoveryFlow) certificateID(serial string) uuid.UUID {
	flow.t.Helper()
	var id uuid.UUID
	if err := flow.pool.QueryRow(flow.t.Context(), `SELECT id FROM node_certificates WHERE node_id=$1 AND serial_number=$2`,
		flow.nodeID, serial).Scan(&id); err != nil {
		flow.t.Fatalf("node certificate %s: %v", serial, err)
	}
	return id
}

func (flow *certRecoveryFlow) count(query string, args ...any) int {
	flow.t.Helper()
	var count int
	if err := flow.pool.QueryRow(flow.t.Context(), query, args...).Scan(&count); err != nil {
		flow.t.Fatal(err)
	}
	return count
}

func certRecoveryMetadata() *commonv1.RequestMetadata {
	id := uuid.Must(uuid.NewV7()).String()
	return &commonv1.RequestMetadata{RequestId: id, SentTime: timestamppb.Now(), CorrelationId: id}
}

func (flow *certRecoveryFlow) expectAuthorized(state certRecoveryAgentState) {
	flow.t.Helper()
	digest, _ := hex.DecodeString(state.CertificateSHA256)
	callCtx, cancel := context.WithTimeout(flow.t.Context(), 10*time.Second)
	defer cancel()
	snapshot, err := flow.control.GetNodeAuthorization(callCtx, &controlv1.GetNodeAuthorizationRequest{
		Request: certRecoveryMetadata(), NodeId: flow.nodeID.String(), CertificateSerialNumber: state.CertificateSerial,
		GatewayInstanceId: uuid.NewString(), CertificateSha256: digest})
	if err != nil || !snapshot.GetConnectionAllowed() {
		flow.t.Fatalf("GetNodeAuthorization(recovered certificate) = (%v, %v)", snapshot, err)
	}
}

// expectOtherKeyRefused sends ControlInternal a recovery of the expired certificate whose CSR and signature belong
// to another Ed25519 key.
func (flow *certRecoveryFlow) expectOtherKeyRefused(expiredSerial string) {
	t := flow.t
	t.Helper()
	var leafPEM []byte
	if err := flow.pool.QueryRow(t.Context(), `SELECT leaf_certificate_pem FROM node_certificates WHERE node_id=$1 AND serial_number=$2`,
		flow.nodeID, expiredSerial).Scan(&leafPEM); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("expired certificate PEM")
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	metadata := certRecoveryMetadata()
	message := nodeidentity.RecoveryMessage(metadata.RequestId, metadata.SentTime.AsTime(), flow.nodeID.String(), block.Bytes, csr, nonce)
	before := flow.count(`SELECT count(*) FROM node_certificate_renewal_requests WHERE node_id=$1`, flow.nodeID) +
		flow.count(`SELECT count(*) FROM node_certificate_recoveries WHERE node_id=$1`, flow.nodeID)
	callCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err = flow.control.RecoverNodeCertificate(callCtx, &controlv1.RecoverNodeCertificateRequest{
		Recovery: &agentv1.RecoverCertificateRequest{Request: metadata, NodeId: flow.nodeID.String(),
			ExpiredCertificateDer: block.Bytes, CertificateSigningRequestDer: csr, Nonce: nonce,
			Signature: ed25519.Sign(otherKey, message)},
		GatewayInstanceId: uuid.NewString()})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("recovery with another key: %v, want PermissionDenied", err)
	}
	after := flow.count(`SELECT count(*) FROM node_certificate_renewal_requests WHERE node_id=$1`, flow.nodeID) +
		flow.count(`SELECT count(*) FROM node_certificate_recoveries WHERE node_id=$1`, flow.nodeID)
	if after != before {
		t.Fatalf("refused recovery wrote rows: %d -> %d", before, after)
	}
}
