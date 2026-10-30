package enrollment

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// interruptedEnrollment leaves the state of an install whose Gateway
// enrollment committed on the controller but whose response was lost: the
// pending directory with pending.json, no identity. It returns the response
// the controller issued for that pending CSR.
func interruptedEnrollment(t *testing.T, fixture *fixture, config Config) *agentv1.EnrollResponse {
	t.Helper()
	var issued *agentv1.EnrollResponse
	config.Dial = func(context.Context, Config) (RPC, io.Closer, error) {
		return rpcFunc(func(_ context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
			issued = fixture.response(t, request)
			return nil, errors.New("response lost")
		}), nil, nil
	}
	if _, err := Run(context.Background(), config, testToken); !errors.Is(err, ErrEnrollmentRejected) {
		t.Fatalf("interrupted Run() error = %v", err)
	}
	if issued == nil || exists(config.IdentityDir) || !exists(filepath.Join(config.IdentityDir+pendingSuffix, pendingFileName)) {
		t.Fatal("interrupted enrollment did not leave pending state")
	}
	return issued
}

func resumeConfig(config Config) ResumeConfig {
	return ResumeConfig{IdentityDir: config.IdentityDir, MachineIDFile: config.MachineIDFile,
		SupportedVersions: config.SupportedVersions, Now: config.Now}
}

func TestResumeAssemblesIdentityFromPendingState(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	issued := interruptedEnrollment(t, fixture, config)

	digest, err := PendingCSRSHA256(config.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readPending(config.IdentityDir + pendingSuffix)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(pending.csrDER)
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("PendingCSRSHA256 = %s", digest)
	}
	response, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Resume(resumeConfig(config), response)
	if err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if result.NodeID != issued.NodeId || exists(config.IdentityDir+pendingSuffix) {
		t.Fatalf("Resume() result = %+v", result)
	}
	assertMode(t, config.IdentityDir, 0o700)
	for _, path := range []string{result.IdentityFile, result.ClientCertificateFile, result.ClientPrivateKeyFile, result.ArtifactPrivateKeyFile} {
		assertMode(t, path, 0o600)
	}
	assertPersistedMTLS(t, fixture, result)
	if _, err := Resume(resumeConfig(config), response); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second Resume() error = %v, want ErrAlreadyEnrolled", err)
	}
}

// The controller writes RFC 3339 timestamps and base64 bytes under the proto
// field names (httpapi nodeRegistrationIdentityResponse); that shape must
// decode as an EnrollResponse.
func TestResumeAcceptsControllerResponseShape(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	issued := interruptedEnrollment(t, fixture, config)
	certificate := issued.Certificate
	body, err := json.Marshal(map[string]any{
		"node_id":                    issued.NodeId,
		"selected_protocol_version":  map[string]uint32{"major": issued.SelectedProtocolVersion.Major, "minor": 0},
		"artifact_encryption_key_id": issued.ArtifactEncryptionKeyId,
		"certificate": map[string]any{
			"leaf_certificate_pem": certificate.LeafCertificatePem, "issuing_chain_pem": certificate.IssuingChainPem,
			"serial_number":   certificate.SerialNumber,
			"not_before_time": certificate.NotBeforeTime.AsTime().UTC().Format(time.RFC3339Nano),
			"expiration_time": certificate.ExpirationTime.AsTime().UTC().Format(time.RFC3339Nano),
			"renewal_time":    certificate.RenewalTime.AsTime().UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Resume(resumeConfig(config), body); err != nil || result.NodeID != issued.NodeId {
		t.Fatalf("Resume(controller shape) = %+v, %v", result, err)
	}
}

func TestResumeRefusesForeignOrMissingState(t *testing.T) {
	t.Run("no pending state", func(t *testing.T) {
		fixture := newFixture(t)
		config := fixture.config(t)
		if _, err := PendingCSRSHA256(config.IdentityDir); !errors.Is(err, ErrRecoveryState) {
			t.Fatalf("PendingCSRSHA256() error = %v", err)
		}
		if _, err := Resume(resumeConfig(config), []byte(`{}`)); !errors.Is(err, ErrRecoveryState) {
			t.Fatalf("Resume() error = %v", err)
		}
	})
	tests := []struct {
		name   string
		change func(*testing.T, *fixture, *agentv1.EnrollResponse) []byte
		want   error
	}{
		{"certificate for another machine's key", func(t *testing.T, fixture *fixture, value *agentv1.EnrollResponse) []byte {
			other := newFixture(t)
			otherConfig := other.config(t)
			interruptedEnrollment(t, other, otherConfig)
			// Same CA and artifact key ID: only the client key binding differs.
			foreign := fixture.response(t, mustPendingRequest(t, otherConfig))
			foreign.ArtifactEncryptionKeyId = value.ArtifactEncryptionKeyId
			encoded, _ := protojson.Marshal(foreign)
			return encoded
		}, ErrInvalidResponse},
		{"artifact key mismatch", func(_ *testing.T, _ *fixture, value *agentv1.EnrollResponse) []byte {
			value.ArtifactEncryptionKeyId = "x25519:" + hex.EncodeToString(make([]byte, 32))
			encoded, _ := protojson.Marshal(value)
			return encoded
		}, ErrInvalidResponse},
		{"unknown field", func(*testing.T, *fixture, *agentv1.EnrollResponse) []byte {
			return []byte(`{"node_id":"x","extra":1}`)
		}, ErrInvalidResponse},
		{"empty", func(*testing.T, *fixture, *agentv1.EnrollResponse) []byte { return nil }, ErrInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			config := fixture.config(t)
			issued := interruptedEnrollment(t, fixture, config)
			if _, err := Resume(resumeConfig(config), test.change(t, fixture, issued)); !errors.Is(err, test.want) {
				t.Fatalf("Resume() error = %v, want %v", err, test.want)
			}
			if exists(config.IdentityDir) || !exists(filepath.Join(config.IdentityDir+pendingSuffix, pendingFileName)) {
				t.Fatal("rejected response committed an identity or lost the pending state")
			}
		})
	}
	t.Run("machine changed", func(t *testing.T) {
		fixture := newFixture(t)
		config := fixture.config(t)
		issued := interruptedEnrollment(t, fixture, config)
		if err := os.WriteFile(config.MachineIDFile, []byte("another-machine\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		encoded, _ := protojson.Marshal(issued)
		if _, err := Resume(resumeConfig(config), encoded); !errors.Is(err, ErrRecoveryState) {
			t.Fatalf("Resume() error = %v, want ErrRecoveryState", err)
		}
	})
}

// mustPendingRequest rebuilds the EnrollRequest fields the issuer needs from
// a pending directory (CSR and artifact public key).
func mustPendingRequest(t *testing.T, config Config) *agentv1.EnrollRequest {
	t.Helper()
	pending, err := readPending(config.IdentityDir + pendingSuffix)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.EnrollRequest{CertificateSigningRequestDer: pending.csrDER,
		ArtifactEncryptionPublicKey: pending.artifactKey.PublicKey().Bytes()}
}

// A rename interrupted after the identity files were written needs no
// controller response.
func TestResumeCommitsHalfCommittedIdentity(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	issued := interruptedEnrollment(t, fixture, config)
	encoded, _ := protojson.Marshal(issued)
	result, err := Resume(resumeConfig(config), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config.IdentityDir, config.IdentityDir+pendingSuffix); err != nil {
		t.Fatal(err)
	}
	again, err := Resume(resumeConfig(config), nil)
	if err != nil || again.NodeID != result.NodeID || !exists(config.IdentityDir) || exists(config.IdentityDir+pendingSuffix) {
		t.Fatalf("half-committed Resume() = %+v, %v", again, err)
	}
}

// edge-enroll-pending-fixture relies on this: the CSR rebuilt from the
// committed client key is byte-identical to the pending one (Ed25519 is
// deterministic), so its digest matches the controller's csr_sha256.
func TestPendingCSRIsReproducibleFromClientKey(t *testing.T) {
	fixture := newFixture(t)
	config := fixture.config(t)
	interruptedEnrollment(t, fixture, config)
	want, err := PendingCSRSHA256(config.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readPending(config.IdentityDir + pendingSuffix)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, pending.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(rebuilt); hex.EncodeToString(digest[:]) != want {
		t.Fatal("CSR rebuilt from the client key differs from the pending CSR")
	}
}
