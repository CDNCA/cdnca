package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/enrollment"
)

func TestExecuteEnrollmentReadsTokenFromStdinAndEmitsSafeResult(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	var received []byte
	runner := func(_ context.Context, config enrollment.Config, value []byte) (enrollment.Result, error) {
		received = bytes.Clone(value)
		if config.Address != "gateway.test:9443" || config.MachineIDFile != "/etc/machine-id" {
			t.Fatalf("enrollment config = %#v", config)
		}
		return enrollment.Result{NodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b717f", ProtocolMajor: 1}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeEnrollment(context.Background(), []string{
		"--gateway-address", "gateway.test:9443", "--gateway-server-name", "gateway.test",
		"--gateway-root-ca-file", "/etc/cdnca-edge-agent/tls/ca.pem",
	}, strings.NewReader(token+"\n"), &stdout, &stderr, runner)
	if code != 0 || string(received) != token || !bytes.Contains(stdout.Bytes(), []byte(`"node_id"`)) {
		t.Fatalf("executeEnrollment() code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte(token)) || bytes.Contains(stderr.Bytes(), []byte(token)) {
		t.Fatal("enrollment token leaked to command output")
	}
}

func TestExecuteEnrollmentDoesNotLogTokenOnFailure(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	runner := func(context.Context, enrollment.Config, []byte) (enrollment.Result, error) {
		return enrollment.Result{}, errors.New("safe failure")
	}
	var stdout, stderr bytes.Buffer
	code := executeEnrollment(context.Background(), []string{
		"--gateway-address", "gateway.test:9443", "--gateway-server-name", "gateway.test",
		"--gateway-root-ca-file", "/etc/cdnca-edge-agent/tls/ca.pem",
	}, strings.NewReader(token), &stdout, &stderr, runner)
	if code == 0 || bytes.Contains(stdout.Bytes(), []byte(token)) || bytes.Contains(stderr.Bytes(), []byte(token)) {
		t.Fatalf("unsafe failure output stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

// W1: without --gateway-address the persisted GatewayHello list's enrollment
// ports are tried in order; a rejected/unreachable one moves to the next.
func TestExecuteEnrollmentFallsBackToPersistedEnrollmentAddresses(t *testing.T) {
	journal := t.TempDir()
	stored := `{"version":"v3","endpoints":[` +
		`{"Address":"cdn.example.com:443","ServerName":"gw.example.com","Transport":"ws","TunnelHost":"cdn.example.com"},` +
		`{"Address":"gw-a.example.com:21444","ServerName":"gw-a.example.com","Transport":"grpc","EnrollmentAddress":"gw-a.example.com:21443"},` +
		`{"Address":"gw-b.example.com:21444","ServerName":"gw-b.example.com","Transport":"grpc","EnrollmentAddress":"gw-b.example.com:21443"}]}`
	if err := os.WriteFile(filepath.Join(journal, "gateway-endpoints.json"), []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	var tried []string
	runner := func(_ context.Context, config enrollment.Config, _ []byte) (enrollment.Result, error) {
		tried = append(tried, config.Address+"/"+config.ServerName+"/"+config.Transport)
		if config.Address == "gw-a.example.com:21443" {
			return enrollment.Result{}, fmt.Errorf("%w: connect to enrollment endpoint", enrollment.ErrEnrollmentRejected)
		}
		return enrollment.Result{NodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b717f", ProtocolMajor: 1}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeEnrollment(context.Background(), []string{
		"--gateway-root-ca-file", "/etc/cdnca-edge-agent/tls/ca.pem", "--journal-dir", journal,
	}, strings.NewReader(token), &stdout, &stderr, runner)
	want := []string{"gw-a.example.com:21443/gw-a.example.com/grpc", "gw-b.example.com:21443/gw-b.example.com/grpc"}
	if code != 0 || strings.Join(tried, ",") != strings.Join(want, ",") {
		t.Fatalf("code=%d tried=%v stderr=%s", code, tried, stderr.String())
	}
}

func TestExecuteEnrollmentStopsOnNonGatewayFailureAndRejectsMissingList(t *testing.T) {
	journal := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x54}, 32))
	calls := 0
	runner := func(context.Context, enrollment.Config, []byte) (enrollment.Result, error) {
		calls++
		return enrollment.Result{}, enrollment.ErrAlreadyEnrolled
	}
	args := []string{"--gateway-root-ca-file", "/etc/cdnca-edge-agent/tls/ca.pem", "--journal-dir", journal}
	var stdout, stderr bytes.Buffer
	if code := executeEnrollment(context.Background(), args, strings.NewReader(token), &stdout, &stderr, runner); code != 2 || calls != 0 {
		t.Fatalf("missing list: code=%d calls=%d", code, calls)
	}
	stored := `{"version":"v1","endpoints":[` +
		`{"Address":"gw-a:21444","ServerName":"gw-a","Transport":"grpc","EnrollmentAddress":"gw-a:21443"},` +
		`{"Address":"gw-b:21444","ServerName":"gw-b","Transport":"grpc","EnrollmentAddress":"gw-b:21443"}]}`
	if err := os.WriteFile(filepath.Join(journal, "gateway-endpoints.json"), []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := executeEnrollment(context.Background(), args, strings.NewReader(token), &stdout, &stderr, runner); code != 1 || calls != 1 {
		t.Fatalf("non-gateway failure must not try the next endpoint: code=%d calls=%d", code, calls)
	}
}

// fz-x13: the resume modes never call the Gateway and refuse to mix with
// enrollment arguments or each other.
func TestExecuteEnrollmentResumeModes(t *testing.T) {
	runner := func(context.Context, enrollment.Config, []byte) (enrollment.Result, error) {
		t.Fatal("resume mode called the Gateway enrollment")
		return enrollment.Result{}, nil
	}
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity")
	for _, args := range [][]string{
		{"--print-pending-csr-sha256", "--recover-from-response", filepath.Join(dir, "r.json")},
		{"--print-pending-csr-sha256", "--gateway-address", "gw:21443"},
		{"--recover-from-response", filepath.Join(dir, "r.json"), "--token-file", filepath.Join(dir, "t")},
		{"--print-pending-csr-sha256", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := executeEnrollment(context.Background(), args, strings.NewReader(""), &stdout, &stderr, runner); code != 2 {
			t.Errorf("%v: code=%d, want 2", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	code := executeEnrollment(context.Background(), []string{"--print-pending-csr-sha256", "--identity-dir", identity},
		strings.NewReader(""), &stdout, &stderr, runner)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "enrollment_resume_failed") {
		t.Fatalf("no pending state: code=%d stdout=%q stderr=%s", code, stdout.String(), stderr.String())
	}
	response := filepath.Join(dir, "response.json")
	if err := os.WriteFile(response, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = executeEnrollment(context.Background(), []string{"--recover-from-response", response, "--identity-dir", identity},
		strings.NewReader(""), &stdout, &stderr, runner)
	if code != 1 || !strings.Contains(stderr.String(), "recovery response rejected") {
		t.Fatalf("group-readable response file: code=%d stderr=%s", code, stderr.String())
	}
}
