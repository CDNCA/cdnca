package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/google/uuid"
)

type orderedCertificateRecoverer struct {
	mu    *sync.Mutex
	order *[]string
	err   error
}

func (recoverer *orderedCertificateRecoverer) Recover(context.Context) (certstore.Result, error) {
	recoverer.mu.Lock()
	defer recoverer.mu.Unlock()
	*recoverer.order = append(*recoverer.order, "certificate")
	return certstore.Result{}, recoverer.err
}

type orderedCertificateDeploymentRecoverer struct {
	mu    *sync.Mutex
	order *[]string
	err   error
}

func (recoverer *orderedCertificateDeploymentRecoverer) RecoverCertificateVersionReferences(context.Context) error {
	recoverer.mu.Lock()
	defer recoverer.mu.Unlock()
	*recoverer.order = append(*recoverer.order, "deployment-references")
	return recoverer.err
}

type orderedGatewayRunner struct {
	mu     *sync.Mutex
	order  *[]string
	closes int
}

func (runner *orderedGatewayRunner) Close() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.closes++
	return nil
}

func (runner *orderedGatewayRunner) Run(context.Context) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	*runner.order = append(*runner.order, "gateway")
	return nil
}

func TestDaemonRecoversCertificateDeploymentReferencesBeforeGateway(t *testing.T) {
	var mu sync.Mutex
	var order []string
	daemon := &daemonClient{
		client:                &orderedGatewayRunner{mu: &mu, order: &order},
		certificate:           &orderedCertificateRecoverer{mu: &mu, order: &order},
		certificateDeployment: &orderedCertificateDeploymentRecoverer{mu: &mu, order: &order},
	}
	if err := daemon.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if want := []string{"certificate", "deployment-references", "gateway"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestDaemonStopsBeforeGatewayWhenCertificateDeploymentRecoveryFails(t *testing.T) {
	var mu sync.Mutex
	var order []string
	daemon := &daemonClient{
		client:      &orderedGatewayRunner{mu: &mu, order: &order},
		certificate: &orderedCertificateRecoverer{mu: &mu, order: &order},
		certificateDeployment: &orderedCertificateDeploymentRecoverer{
			mu: &mu, order: &order, err: errors.New("reference recovery failed"),
		},
	}
	if err := daemon.Run(t.Context()); err == nil {
		t.Fatal("Run() succeeded after certificate deployment recovery failure")
	}
	if want := []string{"certificate", "deployment-references"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestDaemonCloseOwnsGatewayLease(t *testing.T) {
	var mu sync.Mutex
	var order []string
	runner := &orderedGatewayRunner{mu: &mu, order: &order}
	daemon := &daemonClient{client: runner}
	if err := daemon.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := daemon.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if runner.closes != 1 {
		t.Fatalf("gateway closes = %d, want 1", runner.closes)
	}
}

func TestAssembleClientClosesGatewayLeaseAfterPostNewFailure(t *testing.T) {
	root := secureConfigTempDir(t)
	securityDir := filepath.Join(root, "security")
	if err := os.MkdirAll(securityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, publicKeyPEM := testSecurityMaterial(t)
	rootCAFile := writeTestFile(t, securityDir, "ca.pem", certificatePEM, 0o600)
	clientCertificateFile := writeTestFile(t, securityDir, "client.pem", certificatePEM, 0o600)
	clientPrivateKeyFile := writeTestFile(t, securityDir, "client-key.pem", privateKeyPEM, 0o600)
	trustContent, err := json.Marshal(map[string]any{
		"version": 1,
		"keys":    []map[string]string{{"key_id": "artifact-key", "public_key_pem": string(publicKeyPEM)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	trustFile := writeTestFile(t, securityDir, "trust.json", trustContent, 0o400)
	spoolFile := writeTestFile(t, root, "event-spool-file", []byte("not a directory"), 0o600)

	config := validFileConfig()
	config.ArtifactTrustFile = trustFile
	config.DeploymentRoot = filepath.Join(root, "deployments")
	config.JournalDir = filepath.Join(root, "gateway-journal")
	config.CertificateRuntime.StateRoot = filepath.Join(root, "certificates")
	config.Gateway.RootCAFile = rootCAFile
	config.Gateway.ClientCertificate = clientCertificateFile
	config.Gateway.ClientPrivateKeyFile = clientPrivateKeyFile
	config.OpenResty.Binary = trueBinary(t)
	config.Telemetry.Enabled = true
	config.Telemetry.SpoolRoot = spoolFile
	timeouts, err := config.validate()
	if err != nil {
		t.Fatal(err)
	}
	if client, assembleErr := assembleClient(config, timeouts, uuid.NewString()); assembleErr == nil {
		_ = client.(*daemonClient).Close()
		t.Fatal("assembleClient() succeeded with a non-directory telemetry spool")
	}

	if err := os.Remove(spoolFile); err != nil {
		t.Fatal(err)
	}
	config.Telemetry.Enabled = false
	timeouts, err = config.validate()
	if err != nil {
		t.Fatal(err)
	}
	client, err := assembleClient(config, timeouts, uuid.NewString())
	if err != nil {
		t.Fatalf("assembleClient() after failure = %v", err)
	}
	if err := client.(*daemonClient).Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
