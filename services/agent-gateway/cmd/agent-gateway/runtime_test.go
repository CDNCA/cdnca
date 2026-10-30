package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	gateway "github.com/cdnca/cdnca/services/agent-gateway"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestLoadedTLSKeepsEnrollmentAndAgentBoundariesSeparate(t *testing.T) {
	pki := createTestPKI(t)
	cfg := config{
		serverCertificateFile:       pki.serverCertificate,
		serverKeyFile:               pki.serverKey,
		agentClientCAFile:           pki.caCertificate,
		controlCertificateFile:      pki.controlCertificate,
		controlKeyFile:              pki.controlKey,
		controlServerCAFile:         pki.caCertificate,
		controlServerName:           "localhost",
		controlClientWorkloadURISAN: "spiffe://cdn-platform/gateway/control",
	}
	enrollmentTLS, agentTLS, err := loadListenerTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if enrollmentTLS.MinVersion != tls.VersionTLS13 || enrollmentTLS.MaxVersion != tls.VersionTLS13 || enrollmentTLS.ClientAuth != tls.NoClientCert {
		t.Fatalf("enrollment TLS policy = min %d client auth %d", enrollmentTLS.MinVersion, enrollmentTLS.ClientAuth)
	}
	if agentTLS.MinVersion != tls.VersionTLS13 || agentTLS.MaxVersion != tls.VersionTLS13 || agentTLS.ClientAuth != tls.RequireAndVerifyClientCert || agentTLS.ClientCAs == nil {
		t.Fatalf("Agent TLS policy = min %d client auth %d", agentTLS.MinVersion, agentTLS.ClientAuth)
	}
	controlTLS, err := loadControlTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if controlTLS.MinVersion != tls.VersionTLS13 || controlTLS.MaxVersion != tls.VersionTLS13 || controlTLS.ServerName != "localhost" || controlTLS.RootCAs == nil || len(controlTLS.Certificates) != 1 {
		t.Fatal("ControlInternal client did not use strict mTLS")
	}

	serviceConfig := gateway.DefaultConfig()
	serviceConfig.GatewayInstanceID = "018f47a2-5b9c-7d31-8a60-104c9c0b717f"
	serviceConfig.GatewayVersion = "test"
	service, err := gateway.NewWithDurableMessaging(serviceConfig, testControl{}, gateway.NewMemorySessionCoordinator(), testMessaging{}, testMessaging{})
	if err != nil {
		t.Fatal(err)
	}
	servers, err := gateway.NewServers(service, enrollmentTLS, agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentListener := listenLocal(t)
	agentListener := listenLocal(t)
	go func() { _ = servers.Enrollment.Serve(enrollmentListener) }()
	go func() { _ = servers.MTLS.Serve(agentListener) }()
	t.Cleanup(func() {
		servers.Enrollment.Stop()
		servers.MTLS.Stop()
	})

	clientRoots, err := loadCAPool(pki.caCertificate)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentConnection := dialTestGRPC(t, enrollmentListener.Addr().String(), clientRoots)
	defer enrollmentConnection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = agentv1.NewAgentGatewayServiceClient(enrollmentConnection).RenewCertificate(ctx, &agentv1.RenewCertificateRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("enrollment listener exposed an Agent-only RPC: %v", status.Code(err))
	}

	clientCertificate, err := loadCertificate(pki.agentCertificate, pki.agentKey, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	agentConnection := dialTestGRPC(t, agentListener.Addr().String(), clientRoots, clientCertificate)
	defer agentConnection.Close()
	_, err = agentv1.NewAgentGatewayServiceClient(agentConnection).Enroll(ctx, &agentv1.EnrollRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Agent listener exposed enrollment: %v", status.Code(err))
	}

	missingCertificateContext, cancelMissing := context.WithTimeout(context.Background(), time.Second)
	defer cancelMissing()
	connection, err := grpc.DialContext(
		missingCertificateContext,
		agentListener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: clientRoots, ServerName: "localhost"})),
		grpc.WithBlock(),
	)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal("Agent listener accepted a client without a certificate")
	}
}

func TestTelemetryConnectionOptionsUseTLSFirstAndConfiguredRoots(t *testing.T) {
	pki := createTestPKI(t)
	t.Setenv("SSL_CERT_FILE", pki.caCertificate)
	base := config{
		telemetryNATSURL:      "tls://analytics-nats.internal:4222",
		telemetryNATSUser:     "telemetry-user",
		telemetryNATSPassword: "telemetry-password",
		startupTimeout:        time.Second,
		shutdownTimeout:       2 * time.Second,
	}

	options := nats.GetDefaultOptions()
	for _, apply := range telemetryConnectionOptions(base) {
		if err := apply(&options); err != nil {
			t.Fatal(err)
		}
	}
	if !options.TLSHandshakeFirst || !options.Secure || options.RootCAsCB == nil {
		t.Fatal("TLS telemetry options do not require a first handshake with configured roots")
	}
	roots, err := options.RootCAsCB()
	if err != nil || roots == nil || len(roots.Subjects()) == 0 {
		t.Fatalf("telemetry root CA options = roots:%v err:%v", roots != nil, err)
	}
	if options.User != base.telemetryNATSUser || options.Password != base.telemetryNATSPassword {
		t.Fatal("telemetry credentials were not applied to the dedicated connection")
	}

	loopback := base
	loopback.telemetryNATSURL = "nats://127.0.0.1:4222"
	options = nats.GetDefaultOptions()
	for _, apply := range telemetryConnectionOptions(loopback) {
		if err := apply(&options); err != nil {
			t.Fatal(err)
		}
	}
	if options.TLSHandshakeFirst || options.RootCAsCB != nil {
		t.Fatal("loopback cleartext telemetry unexpectedly enabled TLS proxy options")
	}
}

func TestTLSLoadingRejectsWrongCertificateRoleAndNonFileCA(t *testing.T) {
	pki := createTestPKI(t)
	if _, err := loadCertificate(pki.serverCertificate, pki.serverKey, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("server-only certificate accepted for ControlInternal client authentication")
	}
	if _, err := loadCAPool(t.TempDir()); err == nil {
		t.Fatal("directory accepted as a CA file")
	}
}

func TestServeServersStopsBothListenersWhenCanceled(t *testing.T) {
	enrollmentListener := newReadyListener(listenLocal(t))
	agentListener := newReadyListener(listenLocal(t))
	healthListener := listenLocal(t)
	enrollmentServer := grpc.NewServer()
	agentServer := grpc.NewServer()
	liveness := &livenessState{}
	readiness := newRuntimeReadiness(listenerReadiness(enrollmentListener), listenerReadiness(agentListener))
	healthServer := newHealthHTTPServer(newHealthHandler(liveness, readiness, 100*time.Millisecond), 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveServers(
			ctx, enrollmentListener, agentListener, healthListener,
			enrollmentServer, agentServer, healthServer, liveness, time.Second, nil,
		)
	}()
	for _, address := range []string{enrollmentListener.Addr().String(), agentListener.Addr().String()} {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatalf("listener %s did not start: %v", address, err)
		}
		_ = connection.Close()
	}
	waitForHTTPStatus(t, "http://"+healthListener.Addr().String()+"/health/live", http.StatusOK)
	waitForHTTPStatus(t, "http://"+healthListener.Addr().String()+"/health/ready", http.StatusOK)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Gateway and health listeners did not stop within the shutdown bound")
	}
	if liveness.isLive() || enrollmentListener.isReady() || agentListener.isReady() {
		t.Fatal("runtime remained ready after graceful shutdown")
	}
	for _, address := range []string{enrollmentListener.Addr().String(), agentListener.Addr().String(), healthListener.Addr().String()} {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatalf("listener %s remained open after shutdown", address)
		}
	}
}

func TestServeServersFailsClosedWhenHealthServerStops(t *testing.T) {
	enrollmentListener := newReadyListener(listenLocal(t))
	agentListener := newReadyListener(listenLocal(t))
	healthListener := listenLocal(t)
	enrollmentServer := grpc.NewServer()
	agentServer := grpc.NewServer()
	liveness := &livenessState{}
	healthServer := newHealthHTTPServer(newHealthHandler(
		liveness,
		newRuntimeReadiness(listenerReadiness(enrollmentListener), listenerReadiness(agentListener)),
		100*time.Millisecond,
	), 100*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		done <- serveServers(
			context.Background(), enrollmentListener, agentListener, healthListener,
			enrollmentServer, agentServer, healthServer, liveness, time.Second, nil,
		)
	}()
	waitForHTTPStatus(t, "http://"+healthListener.Addr().String()+"/health/ready", http.StatusOK)
	if err := healthListener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "health HTTP server stopped" {
			t.Fatalf("health failure result = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("health listener failure did not stop the Gateway")
	}
	if liveness.isLive() || enrollmentListener.isReady() || agentListener.isReady() {
		t.Fatal("health listener failure left the Gateway ready")
	}
	for _, address := range []string{enrollmentListener.Addr().String(), agentListener.Addr().String()} {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatalf("gRPC listener %s remained open after health failure", address)
		}
	}
}

func TestServeServersFailsClosedWhenAgentListenerStops(t *testing.T) {
	enrollmentListener := newReadyListener(listenLocal(t))
	agentListener := newReadyListener(listenLocal(t))
	healthListener := listenLocal(t)
	enrollmentServer := grpc.NewServer()
	agentServer := grpc.NewServer()
	liveness := &livenessState{}
	healthServer := newHealthHTTPServer(newHealthHandler(
		liveness,
		newRuntimeReadiness(listenerReadiness(enrollmentListener), listenerReadiness(agentListener)),
		100*time.Millisecond,
	), 100*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		done <- serveServers(
			context.Background(), enrollmentListener, agentListener, healthListener,
			enrollmentServer, agentServer, healthServer, liveness, time.Second, nil,
		)
	}()
	waitForHTTPStatus(t, "http://"+healthListener.Addr().String()+"/health/ready", http.StatusOK)
	if err := agentListener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "Agent mTLS gRPC server stopped" {
			t.Fatalf("Agent listener failure result = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Agent listener failure did not stop the runtime")
	}
	if liveness.isLive() || enrollmentListener.isReady() || agentListener.isReady() {
		t.Fatal("Agent listener failure left the runtime ready")
	}
	connection, err := net.DialTimeout("tcp", healthListener.Addr().String(), 50*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("health listener remained open after Agent listener failure")
	}
}

// After a port transition was finalized the old Agent listener is closed on
// purpose; an unplanned stop of the new one must still stop the runtime
// (final-fix-b: it used to keep running without an Agent listener).
func TestServeServersFailsClosedWhenTransitionListenerStops(t *testing.T) {
	enrollmentListener := newReadyListener(listenLocal(t))
	agentListener := newReadyListener(listenLocal(t))
	healthListener := listenLocal(t)
	enrollmentServer := grpc.NewServer()
	agentServer := grpc.NewServer()
	liveness := &livenessState{}
	healthServer := newHealthHTTPServer(newHealthHandler(
		liveness,
		newRuntimeReadiness(listenerReadiness(enrollmentListener), listenerReadiness(agentListener)),
		100*time.Millisecond,
	), 100*time.Millisecond)
	transitionErrors := make(chan serveResult, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveServers(
			context.Background(), enrollmentListener, agentListener, healthListener,
			enrollmentServer, agentServer, healthServer, liveness, time.Second, transitionErrors,
		)
	}()
	waitForHTTPStatus(t, "http://"+healthListener.Addr().String()+"/health/ready", http.StatusOK)
	// Finalize: the old listener goes away as planned, the runtime keeps serving.
	agentListener.MarkPlannedClose()
	if err := agentListener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("planned close of the old Agent listener stopped the runtime: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	// The promoted listener stops unexpectedly.
	newListener := newReadyListener(listenLocal(t))
	served := make(chan error, 1)
	go reportTransitionServeStop(served, newListener, transitionErrors)
	served <- net.ErrClosed
	select {
	case err := <-done:
		if err == nil || err.Error() != "Agent mTLS gRPC server stopped" {
			t.Fatalf("transition listener failure result = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transition listener failure did not stop the runtime")
	}
	if liveness.isLive() {
		t.Fatal("transition listener failure left the runtime live")
	}
	connection, err := net.DialTimeout("tcp", healthListener.Addr().String(), 50*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("health listener remained open after transition listener failure")
	}
}

func TestReportTransitionServeStopIgnoresPlannedClose(t *testing.T) {
	listener := newReadyListener(listenLocal(t))
	listener.MarkPlannedClose()
	served := make(chan error, 1)
	target := make(chan serveResult, 1)
	served <- net.ErrClosed
	reportTransitionServeStop(served, listener, target)
	select {
	case result := <-target:
		t.Fatalf("planned close reported as failure: %+v", result)
	default:
	}
}

func TestBindListenersClosesPartialRuntimeOnHealthConflict(t *testing.T) {
	occupied := listenLocal(t)
	r := &runtime{}
	err := r.bindListeners(config{
		enrollmentAddress: "127.0.0.1:0",
		agentAddress:      "127.0.0.1:0",
		healthAddress:     occupied.Addr().String(),
	})
	if err == nil || err.Error() != "bind health listener" {
		t.Fatalf("health bind conflict = %v", err)
	}
	for _, listener := range []*readyListener{r.enrollmentListener, r.agentListener} {
		connection, dialError := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond)
		if dialError == nil {
			_ = connection.Close()
			t.Fatalf("partial listener %s remained open", listener.Addr())
		}
	}
}

func TestBuildRuntimeEarlyTLSFailurePreservesStageError(t *testing.T) {
	runtimeValue, err := buildRuntime(context.Background(), config{
		serverCertificateFile: filepath.Join(t.TempDir(), "missing-cert.pem"),
		serverKeyFile:         filepath.Join(t.TempDir(), "missing-key.pem"),
		startupTimeout:        time.Second,
		shutdownTimeout:       time.Second,
	})
	if runtimeValue != nil {
		t.Fatal("early TLS failure returned a runtime")
	}
	if err == nil || err.Error() != "load Gateway server certificate" {
		t.Fatalf("early TLS failure = %v", err)
	}
}

func TestMarkRuntimeNotReadyAcceptsUninitializedRuntime(t *testing.T) {
	markRuntimeNotReady(nil, nil)
	(&runtime{}).close()
}

func TestRuntimeNilDependenciesFailClosed(t *testing.T) {
	if err := verifyJetStream(nil, nil, gateway.DefaultNATSCommandBusConfig()); err == nil {
		t.Fatal("nil JetStream dependencies were accepted")
	}
	if err := verifyJetStream(context.Background(), nil, gateway.DefaultNATSCommandBusConfig()); err == nil {
		t.Fatal("nil NATS connection was accepted")
	}
	if runtimeValue, err := buildRuntime(nil, config{}); runtimeValue != nil || err == nil {
		t.Fatalf("nil build context result runtime=%v err=%v", runtimeValue, err)
	}
	var nilRuntime *runtime
	nilRuntime.close()
}

func waitForHTTPStatus(t *testing.T, target string, expected int) {
	t.Helper()
	client := http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(target)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == expected {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not return HTTP %d", target, expected)
}

func TestValidateStreamInfoRequiresDurableCoveredSubject(t *testing.T) {
	valid := &nats.StreamInfo{Config: nats.StreamConfig{
		Subjects: []string{"cdnca.agent.commands.*"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute,
	}}
	if err := validateStreamInfo(valid, "cdnca.agent.commands"); err != nil {
		t.Fatalf("valid stream rejected: %v", err)
	}
	tests := []struct {
		name string
		info *nats.StreamInfo
	}{
		{name: "memory storage", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: valid.Config.Subjects, Storage: nats.MemoryStorage, Replicas: 1, Duplicates: time.Minute}}},
		{name: "no deduplication", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: valid.Config.Subjects, Storage: nats.FileStorage, Replicas: 1}}},
		{name: "wrong subject", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: []string{"other.>"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute}}},
		{name: "terminal wildcard", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: []string{"cdnca.agent.commands.>"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute}}},
		{name: "wildcard prefix", info: &nats.StreamInfo{Config: nats.StreamConfig{Subjects: []string{"cdnca.*.commands.*"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStreamInfo(test.info, "cdnca.agent.commands"); err == nil {
				t.Fatal("invalid stream configuration was accepted")
			}
		})
	}
	literalOnly := &nats.StreamInfo{Config: nats.StreamConfig{
		Subjects: []string{"cdnca.agent.commands.node"}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute,
	}}
	if err := validateStreamInfo(literalOnly, "cdnca.agent.commands"); err == nil {
		t.Fatal("literal-only Agent subject was accepted")
	}
	narrowUpgradeStatus := &nats.StreamInfo{Config: nats.StreamConfig{
		Subjects: []string{gateway.UpgradeStatusSubjectPrefix + ".*"}, Storage: nats.FileStorage,
		Replicas: 1, Duplicates: time.Minute,
	}}
	if err := validateStreamInfo(narrowUpgradeStatus, gateway.UpgradeStatusSubjectPrefix); err != nil {
		t.Fatalf("upgrade status subject rejected: %v", err)
	}
	if err := validateStreamInfo(narrowUpgradeStatus, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
		t.Fatal("readiness accepted a stream that excludes upgrade proof subjects")
	}
}

func TestValidateStreamInfoRequiresExactNonEvictingUpgradeProofSubjects(t *testing.T) {
	proofSubjects := map[string]string{
		"pending":   gateway.UpgradeStatusProofSubjectPrefix + ".pending.*",
		"confirmed": gateway.UpgradeStatusProofSubjectPrefix + ".confirmed.*.*",
		"completed": gateway.UpgradeStatusProofSubjectPrefix + ".completed.*.*.*",
		"status":    gateway.UpgradeStatusProofSubjectPrefix + ".status.*.*",
	}
	allProofSubjects := []string{
		gateway.UpgradeStatusSubjectPrefix + ".*", "cdnca.agent.deployment-status.upgrade-v2.*",
		proofSubjects["pending"], proofSubjects["confirmed"],
		proofSubjects["completed"], proofSubjects["status"],
	}
	valid := &nats.StreamInfo{Config: nats.StreamConfig{
		Name: "AGENT_DEPLOYMENT_STATUS", Subjects: allProofSubjects, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute, Discard: nats.DiscardOld,
		MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
	}}
	if err := validateStreamInfo(valid, gateway.UpgradeStatusProofSubjectPrefix); err != nil {
		t.Fatalf("valid immutable proof stream rejected: %v", err)
	}
	if err := validateStreamSubjectAllowSet(valid.Config.Subjects, allProofSubjects); err != nil {
		t.Fatalf("exact proof subject allow-set rejected: %v", err)
	}
	for _, candidate := range []struct {
		subject       string
		unsafePattern bool
	}{
		{subject: gateway.UpgradeStatusProofSubjectPrefix + ".>", unsafePattern: true},
		{subject: "cdnca.*.deployment-status.*", unsafePattern: true},
		{subject: gateway.UpgradeStatusProofSubjectPrefix + ".pending.fixed", unsafePattern: true},
		{subject: "cdnca.agent.unrelated.*"},
	} {
		mixed := append(append([]string(nil), allProofSubjects...), candidate.subject)
		if err := validateStreamInfo(&nats.StreamInfo{Config: nats.StreamConfig{
			Name: "AGENT_DEPLOYMENT_STATUS", Subjects: mixed, Retention: nats.LimitsPolicy,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute, Discard: nats.DiscardOld,
			MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
		}}, gateway.UpgradeStatusProofSubjectPrefix); candidate.unsafePattern && err == nil {
			t.Fatalf("mixed unsafe subject %q was accepted", candidate.subject)
		}
		if err := validateStreamSubjectAllowSet(mixed, allProofSubjects); err == nil {
			t.Fatalf("extra subject %q was accepted by the exact allow-set", candidate.subject)
		}
	}
	for name, subject := range proofSubjects {
		t.Run(name+" exact", func(t *testing.T) {
			if !streamCoversDynamicSubject([]string{subject}, gateway.UpgradeStatusProofSubjectPrefix,
				map[string][]string{
					"pending": {"pending", "*"}, "confirmed": {"confirmed", "*", "*"},
					"completed": {"completed", "*", "*", "*"}, "status": {"status", "*", "*"},
				}[name], 1) {
				t.Fatalf("exact %s proof subject was rejected", name)
			}
		})
		t.Run(name+" cannot use broad substitute", func(t *testing.T) {
			candidate := *valid
			candidate.Config.Subjects = []string{gateway.UpgradeStatusProofSubjectPrefix + ".>"}
			for otherName, otherSubject := range proofSubjects {
				if otherName != name {
					candidate.Config.Subjects = append(candidate.Config.Subjects, otherSubject)
				}
			}
			if err := validateStreamInfo(&candidate, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
				t.Fatalf("broad wildcard substituted for the %s proof shape", name)
			}
		})
	}

	badSubjects := [][]string{
		{gateway.UpgradeStatusProofSubjectPrefix + ".*"},
		{gateway.UpgradeStatusProofSubjectPrefix + ".pending.*", gateway.UpgradeStatusProofSubjectPrefix + ".confirmed.*.*"},
		{gateway.UpgradeStatusProofSubjectPrefix + ".pending.*", gateway.UpgradeStatusProofSubjectPrefix + ".completed.*.*.*"},
		{gateway.UpgradeStatusProofSubjectPrefix + ".confirmed.*.*", gateway.UpgradeStatusProofSubjectPrefix + ".completed.*.*.*"},
	}
	for index, subjects := range badSubjects {
		candidate := *valid
		candidate.Config.Subjects = subjects
		if err := validateStreamInfo(&candidate, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
			t.Fatalf("proof subject case %d was accepted: %v", index, subjects)
		}
	}

	mutations := []struct {
		name   string
		mutate func(*nats.StreamConfig)
	}{
		{name: "max age", mutate: func(c *nats.StreamConfig) { c.MaxAge = time.Hour }},
		{name: "max messages", mutate: func(c *nats.StreamConfig) { c.MaxMsgs = 100 }},
		{name: "max bytes", mutate: func(c *nats.StreamConfig) { c.MaxBytes = 1 << 20 }},
		{name: "max per subject", mutate: func(c *nats.StreamConfig) { c.MaxMsgsPerSubject = 1 }},
		{name: "discard new", mutate: func(c *nats.StreamConfig) { c.Discard = nats.DiscardNew }},
		{name: "discard per subject", mutate: func(c *nats.StreamConfig) { c.DiscardNewPerSubject = true }},
		{name: "interest retention", mutate: func(c *nats.StreamConfig) { c.Retention = nats.InterestPolicy }},
		{name: "rollup", mutate: func(c *nats.StreamConfig) { c.AllowRollup = true }},
		{name: "message ttl", mutate: func(c *nats.StreamConfig) { c.AllowMsgTTL = true }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := *valid
			candidate.Config.Subjects = append([]string(nil), valid.Config.Subjects...)
			mutation.mutate(&candidate.Config)
			if err := validateStreamInfo(&candidate, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
				t.Fatal("evicting proof stream was accepted")
			}
		})
	}
}

func TestGatewayRuntimeRequiresExactUpgradeV2StatusSubject(t *testing.T) {
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "gateway.UpgradeStatusV2SubjectPrefix") {
		t.Fatal("Gateway readiness does not require the exact upgrade-v2 StatusID subject")
	}
}

func TestGatewayRuntimeRequiresOrderedLegacyAndEventDeploymentStatusSubjects(t *testing.T) {
	prefix := gateway.DefaultNATSCommandBusConfig().StatusSubjectPrefix
	want := []string{
		prefix + ".*",
		prefix + ".generic-v2.*.*",
		prefix + ".terminal-receipt.*.*",
		prefix + ".terminal-receipt-confirmation.*.*",
		prefix + ".terminal-receipt-confirmation-index.*",
	}
	if err := validateStreamSubjectAllowSet(append([]string(nil), want...), want); err != nil {
		t.Fatalf("canonical deployment status subjects rejected: %v", err)
	}
	for name, subjects := range map[string][]string{
		"legacy only":      {want[0]},
		"event only":       {want[1]},
		"missing receipts": {want[0], want[1]},
		"reordered":        {want[1], want[0], want[2], want[3], want[4]},
		"extra":            {want[0], want[1], want[2], want[3], want[4], prefix + ".>"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStreamSubjectAllowSet(subjects, want); err == nil {
				t.Fatal("drifted deployment status subject allow-set was accepted")
			}
		})
	}

	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`c.StatusSubjectPrefix+".generic-v2.*.*"`,
		`c.StatusSubjectPrefix+".terminal-receipt.*.*"`,
		`c.StatusSubjectPrefix+".terminal-receipt-confirmation.*.*"`,
		`c.StatusSubjectPrefix+".terminal-receipt-confirmation-index.*"`,
	} {
		if !strings.Contains(string(source), required) {
			t.Fatalf("Gateway readiness does not require %s", required)
		}
	}
}

// Control API quarantines poison cache statuses on the deployment status
// stream (cachecontrolruntime PublishDLQ); readiness must refuse a status
// stream that cannot accept them, or cache purge silently loses evidence.
func TestGatewayRuntimeRequiresCacheStatusDLQSubject(t *testing.T) {
	info := &nats.StreamInfo{Config: nats.StreamConfig{
		Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute,
		Subjects: []string{gateway.CacheStatusSubjectPrefix + ".*"},
	}}
	if err := validateStreamInfo(info, gateway.CacheStatusSubjectPrefix+"-dlq"); err == nil {
		t.Fatal("status stream without the cache DLQ subject was accepted")
	}
	info.Config.Subjects = append(info.Config.Subjects, gateway.CacheStatusSubjectPrefix+"-dlq.*")
	if err := validateStreamInfo(info, gateway.CacheStatusSubjectPrefix+"-dlq"); err != nil {
		t.Fatalf("status stream with the cache DLQ subject rejected: %v", err)
	}
	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `{name: c.StatusStream, prefix: gateway.CacheStatusSubjectPrefix + "-dlq"}`) {
		t.Fatal("Gateway readiness does not require the cache status DLQ subject")
	}
}

func TestValidateStreamInfoRejectsLiteralOnlyUpgradeProofSubjects(t *testing.T) {
	info := &nats.StreamInfo{Config: nats.StreamConfig{
		Name: "AGENT_DEPLOYMENT_STATUS", Subjects: []string{
			gateway.UpgradeStatusProofSubjectPrefix + ".pending.node",
			gateway.UpgradeStatusProofSubjectPrefix + ".confirmed.node." + strings.Repeat("0", 64),
			gateway.UpgradeStatusProofSubjectPrefix + ".completed.node.installation.command",
		}, Retention: nats.LimitsPolicy, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute,
		Discard: nats.DiscardOld, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1,
	}}
	if err := validateStreamInfo(info, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
		t.Fatal("literal-only proof subjects were accepted")
	}
}

func TestValidateStreamInfoRejectsCanonicalLiteralSubjects(t *testing.T) {
	const nodeID = "018f47a2-5b9c-7d31-8a60-104c9c0b717f"
	const installationID = "018f47a2-5b9c-7d31-8a60-104c9c0b717e"
	const commandID = "018f47a2-5b9c-7d31-8a60-104c9c0b717d"
	const statusID = "018f47a2-5b9c-7d31-8a60-104c9c0b717c"
	const digest = "0000000000000000000000000000000000000000000000000000000000000000"
	info := &nats.StreamInfo{Config: nats.StreamConfig{
		Name: "AGENT_DEPLOYMENT_STATUS", Subjects: []string{
			gateway.UpgradeCommandSubjectPrefix + "." + nodeID,
		}, Storage: nats.FileStorage, Replicas: 1, Duplicates: time.Minute,
	}}
	if err := validateStreamInfo(info, gateway.UpgradeCommandSubjectPrefix); err == nil {
		t.Fatal("canonical literal command subject was accepted")
	}

	proof := *info
	proof.Config.Subjects = []string{
		gateway.UpgradeStatusProofSubjectPrefix + ".pending." + nodeID,
		gateway.UpgradeStatusProofSubjectPrefix + ".confirmed." + nodeID + "." + digest,
		gateway.UpgradeStatusProofSubjectPrefix + ".completed." + nodeID + "." + installationID + "." + commandID,
		gateway.UpgradeStatusProofSubjectPrefix + ".status." + nodeID + "." + statusID,
	}
	proof.Config.Retention = nats.LimitsPolicy
	proof.Config.Discard = nats.DiscardOld
	proof.Config.MaxMsgs = -1
	proof.Config.MaxBytes = -1
	proof.Config.MaxMsgsPerSubject = -1
	if err := validateStreamInfo(&proof, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
		t.Fatal("canonical literal proof subjects were accepted")
	}

	malformed := proof
	malformed.Config.Subjects = []string{gateway.UpgradeStatusProofSubjectPrefix + ".>.extra"}
	if err := validateStreamInfo(&malformed, gateway.UpgradeStatusProofSubjectPrefix); err == nil {
		t.Fatal("non-terminal proof wildcard was accepted")
	}
}

type testControl struct{}

func (testControl) AuthorizeEnrollment(context.Context, *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	return nil, fmt.Errorf("not called")
}
func (testControl) CompleteEnrollment(context.Context, *controlv1.CompleteEnrollmentRequest) (*controlv1.CompleteEnrollmentResponse, error) {
	return nil, fmt.Errorf("not called")
}
func (testControl) RenewNodeCertificate(context.Context, *controlv1.RenewNodeCertificateRequest) (*controlv1.RenewNodeCertificateResponse, error) {
	return nil, fmt.Errorf("not called")
}
func (testControl) GetNodeAuthorization(context.Context, *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	return nil, fmt.Errorf("not called")
}
func (testControl) FetchArtifact(context.Context, *controlv1.FetchArtifactRequest) (gateway.ArtifactStream, error) {
	return testArtifactStream{}, nil
}

type testArtifactStream struct{}

func (testArtifactStream) Recv() (*controlv1.FetchArtifactResponse, error) { return nil, io.EOF }

type testMessaging struct{}

func (testMessaging) Subscribe(context.Context, string) (gateway.CommandSubscription, error) {
	return nil, fmt.Errorf("not called")
}
func (testMessaging) PublishStatus(context.Context, string,
	*agentv1.DeploymentStatus,
) (gateway.DeploymentStatusPublication, error) {
	return gateway.DeploymentStatusPublication{}, fmt.Errorf("not called")
}
func (testMessaging) PersistHeartbeat(context.Context, string, *agentv1.Heartbeat) error {
	return fmt.Errorf("not called")
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func dialTestGRPC(t *testing.T, address string, roots *x509.CertPool, certificates ...tls.Certificate) *grpc.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", Certificates: certificates,
		})),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

type testPKIPaths struct {
	ca                 *x509.Certificate
	caKey              *ecdsa.PrivateKey
	caCertificate      string
	serverCertificate  string
	serverKey          string
	controlCertificate string
	controlKey         string
	agentCertificate   string
	agentKey           string
}

func createTestPKI(t *testing.T) testPKIPaths {
	t.Helper()
	directory := t.TempDir()
	caKey := newTestKey(t)
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	paths := testPKIPaths{ca: caCertificate, caKey: caKey, caCertificate: writeTestPEM(t, directory, "ca.crt", "CERTIFICATE", caDER)}
	paths.serverCertificate, paths.serverKey = createTestLeaf(t, directory, "server", 2, caCertificate, caKey, x509.ExtKeyUsageServerAuth, nil)
	controlURI, err := url.Parse("spiffe://cdn-platform/gateway/control")
	if err != nil {
		t.Fatal(err)
	}
	paths.controlCertificate, paths.controlKey = createTestLeaf(t, directory, "control", 3, caCertificate, caKey, x509.ExtKeyUsageClientAuth, []*url.URL{controlURI})
	agentURI, err := url.Parse("spiffe://cdn-platform/node/018f47a2-5b9c-7d31-8a60-104c9c0b717f")
	if err != nil {
		t.Fatal(err)
	}
	paths.agentCertificate, paths.agentKey = createTestLeaf(t, directory, "agent", 4, caCertificate, caKey, x509.ExtKeyUsageClientAuth, []*url.URL{agentURI})
	return paths
}

func createTestLeaf(t *testing.T, directory, name string, serial int64, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage, uris []*url.URL) (string, string) {
	return createTestLeafWithUsages(t, directory, name, serial, ca, caKey, []x509.ExtKeyUsage{usage}, uris)
}

func createTestLeafWithUsages(t *testing.T, directory, name string, serial int64, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usages []x509.ExtKeyUsage, uris []*url.URL) (string, string) {
	t.Helper()
	key := newTestKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		DNSNames: []string{"localhost"}, URIs: uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestPEM(t, directory, name+".crt", "CERTIFICATE", der), writeTestPEM(t, directory, name+".key", "PRIVATE KEY", keyDER)
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeTestPEM(t *testing.T, directory, name, blockType string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: contents}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
