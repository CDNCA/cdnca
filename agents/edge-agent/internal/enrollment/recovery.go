package enrollment

// Expired certificate self-recovery (ADR 0013 section 6.1 b, GW-02). When the
// client certificate expired while the node could not reach the control
// plane, the agent sends RecoverCertificate to the Gateway enrollment
// listener (server TLS, no client certificate): the expired certificate, a CSR
// for the same Ed25519 key and a nonce, signed with that key. The request is
// persisted (recovery.json) before it is sent, so a lost response is retried
// with the same request and the control plane replays the issued certificate.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	recoveryStateFileName  = "recovery.json"
	recoveryProofTag       = "cdnca/node-certificate-recovery/v1"
	recoveryInitialBackoff = 30 * time.Second
	recoveryMaximumBackoff = 10 * time.Minute
	// recoveryStateMaxAge bounds how long one persisted request is resent: the
	// control plane accepts a new request only within 5 minutes of sent_time,
	// and replays an issued one at any time.
	recoveryStateMaxAge = 4 * time.Minute
)

var (
	// ErrRecoveryRefused: the control plane refused recovery for good (revoked,
	// recovery window exceeded, other key): manual re-enrollment is required.
	ErrRecoveryRefused = errors.New("certificate recovery was refused; re-enroll the node")
	// ErrRecoveryUnavailable: the Gateway or control plane is unreachable or busy; retry later.
	ErrRecoveryUnavailable = errors.New("certificate recovery is unavailable")
)

// RecoveryRPC is the enrollment listener client.
type RecoveryRPC interface {
	RecoverCertificate(context.Context, *agentv1.RecoverCertificateRequest, ...grpc.CallOption) (*agentv1.RecoverCertificateResponse, error)
}

// RecoveryDialer opens the enrollment listener (Dial with RecoverConfig).
type RecoveryDialer func(context.Context) (RecoveryRPC, io.Closer, error)

type RecoverConfig struct {
	IdentityDir string
	Dial        RecoveryDialer
	Now         func() time.Time
	Random      io.Reader
}

// Recoverer recovers an expired client certificate. It is safe for concurrent use.
type Recoverer struct {
	config     RecoverConfig
	mu         sync.Mutex
	retryAfter time.Time
	backoff    time.Duration
}

type recoveryState struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	SentTime  string `json:"sent_time"`
	// CertificateSHA256 names the expired certificate the request recovers.
	CertificateSHA256 string `json:"certificate_sha256"`
	CSRDER            string `json:"certificate_signing_request_der"`
	Nonce             string `json:"nonce"`
	Signature         string `json:"signature"`
}

// RecoveryMessage is the canonical signed message; control-api
// internal/nodeidentity.RecoveryMessage builds the same bytes (shared test vector).
func RecoveryMessage(requestID string, sentTime time.Time, nodeID string, certificateDER, csrDER, nonce []byte) []byte {
	certificateDigest, csrDigest := sha256.Sum256(certificateDER), sha256.Sum256(csrDER)
	return []byte(strings.Join([]string{
		recoveryProofTag,
		"request_id=" + requestID,
		"sent_time=" + sentTime.UTC().Format(time.RFC3339Nano),
		"node_id=" + nodeID,
		"certificate_sha256=" + hex.EncodeToString(certificateDigest[:]),
		"csr_sha256=" + hex.EncodeToString(csrDigest[:]),
		"nonce=" + hex.EncodeToString(nonce),
	}, "\n"))
}

// RecoveryDial dials the enrollment listener named by config (Address,
// ServerName, RootCAFile) with server-authenticated TLS, as Dial does.
func RecoveryDial(config Config) RecoveryDialer {
	return func(ctx context.Context) (RecoveryRPC, io.Closer, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		rpc, closer, err := Dial(dialCtx, config)
		if err != nil {
			return nil, nil, err
		}
		recovery, ok := rpc.(RecoveryRPC)
		if !ok {
			_ = closer.Close()
			return nil, nil, fmt.Errorf("%w: enrollment client cannot recover certificates", ErrInvalidInput)
		}
		return recovery, closer, nil
	}
}

func NewRecoverer(config RecoverConfig) (*Recoverer, error) {
	if config.Dial == nil || validateSecureDirectory(config.IdentityDir) != nil {
		return nil, fmt.Errorf("%w: certificate recoverer is incomplete", ErrInvalidInput)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Recoverer{config: config}, nil
}

// RecoveryDue reports whether the client certificate has expired.
func (recoverer *Recoverer) RecoveryDue() bool {
	identity, err := LoadIdentityAllowingExpired(recoverer.config.IdentityDir, recoverer.config.Now())
	clear(identity.ArtifactEncryptionPrivateKey)
	return err == nil && identity.CertificateExpired
}

// Recover replaces an expired client certificate. It returns (false, nil)
// while backing off (30s doubling to 10min) or when the certificate is valid,
// ErrRecoveryRefused when only re-enrollment helps, and the new certificate's
// SHA-256 on success.
func (recoverer *Recoverer) Recover(ctx context.Context) (bool, string, error) {
	recoverer.mu.Lock()
	defer recoverer.mu.Unlock()
	now := recoverer.config.Now().UTC()
	if now.Before(recoverer.retryAfter) {
		return false, "", nil
	}
	identity, err := loadRecoveryIdentity(recoverer.config.IdentityDir, now)
	if err != nil {
		return false, "", err
	}
	if now.Before(identity.leaf.NotAfter) {
		recoverer.backoff = 0
		return false, "", nil
	}
	state, err := recoverer.loadOrCreateState(identity, now)
	if err != nil {
		return false, "", err
	}
	request, err := recoveryRequest(state, identity)
	if err != nil {
		return false, "", err
	}
	rpc, closer, err := recoverer.config.Dial(ctx)
	if err != nil {
		recoverer.delay(now)
		return false, "", fmt.Errorf("%w: %v", ErrRecoveryUnavailable, err)
	}
	response, err := rpc.RecoverCertificate(ctx, request, grpc.WaitForReady(false))
	_ = closer.Close()
	if err != nil {
		recoverer.delay(now)
		switch status.Code(err) {
		case codes.PermissionDenied, codes.NotFound:
			return false, "", fmt.Errorf("%w: %v", ErrRecoveryRefused, status.Convert(err).Message())
		case codes.InvalidArgument, codes.AlreadyExists, codes.FailedPrecondition:
			// The persisted request is unusable (e.g. expired before it was issued): start over.
			_ = recoverer.removeState()
		}
		return false, "", fmt.Errorf("%w: %v", ErrRecoveryUnavailable, err)
	}
	certificatePEM, certificateSHA, err := validateRenewalResponse(&agentv1.RenewCertificateResponse{Certificate: response.GetCertificate()},
		identity, now)
	if err != nil {
		recoverer.delay(now)
		return false, "", err
	}
	if err := replaceRenewedCertificate(filepath.Join(recoverer.config.IdentityDir, clientCertFileName),
		recoverer.config.IdentityDir, certificatePEM, identity.certificatePEM, now); err != nil {
		return false, "", err
	}
	_ = recoverer.removeState()
	recoverer.retryAfter, recoverer.backoff = time.Time{}, 0
	return true, certificateSHA, nil
}

func (recoverer *Recoverer) delay(now time.Time) {
	if recoverer.backoff < recoveryInitialBackoff {
		recoverer.backoff = recoveryInitialBackoff
	} else if recoverer.backoff *= 2; recoverer.backoff > recoveryMaximumBackoff {
		recoverer.backoff = recoveryMaximumBackoff
	}
	recoverer.retryAfter = now.Add(recoverer.backoff)
}

func (recoverer *Recoverer) removeState() error {
	err := os.Remove(filepath.Join(recoverer.config.IdentityDir, recoveryStateFileName))
	if err == nil {
		_ = syncDirectory(recoverer.config.IdentityDir)
	}
	return err
}

// loadRecoveryIdentity is loadRenewalIdentity for an expired certificate.
func loadRecoveryIdentity(directory string, now time.Time) (renewalIdentity, error) {
	state, artifactKey, _, err := loadIdentityAt(directory, now, true)
	clear(artifactKey)
	if err != nil {
		return renewalIdentity{}, err
	}
	return loadRenewalKeyPair(directory, state)
}

func (recoverer *Recoverer) loadOrCreateState(identity renewalIdentity, now time.Time) (recoveryState, error) {
	path := filepath.Join(recoverer.config.IdentityDir, recoveryStateFileName)
	digest := hex.EncodeToString(identity.digest[:])
	if exists(path) {
		content, err := readRegular(path, maxSecurityFile, true)
		var state recoveryState
		if err == nil && json.Unmarshal(content, &state) == nil && state.Version == 1 && state.CertificateSHA256 == digest {
			if sent, err := time.Parse(time.RFC3339Nano, state.SentTime); err == nil && now.Sub(sent) < recoveryStateMaxAge {
				return state, nil
			}
		}
		if err := recoverer.removeState(); err != nil {
			return recoveryState{}, fmt.Errorf("%w: clear stale recovery state", ErrPersistence)
		}
	}
	requestID, err := uuid.NewV7FromReader(recoverer.config.Random)
	if err != nil {
		return recoveryState{}, fmt.Errorf("%w: create recovery request ID", ErrPersistence)
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(recoverer.config.Random, nonce); err != nil {
		return recoveryState{}, fmt.Errorf("%w: create recovery nonce", ErrPersistence)
	}
	csrDER, err := x509.CreateCertificateRequest(recoverer.config.Random, &x509.CertificateRequest{
		Subject: pkix.Name{SerialNumber: requestID.String()},
	}, identity.privateKey)
	if err != nil {
		return recoveryState{}, fmt.Errorf("%w: create recovery CSR", ErrPersistence)
	}
	sent := now.Truncate(time.Millisecond)
	message := RecoveryMessage(requestID.String(), sent, identity.state.NodeID, identity.leaf.Raw, csrDER, nonce)
	state := recoveryState{Version: 1, RequestID: requestID.String(), SentTime: sent.Format(time.RFC3339Nano),
		CertificateSHA256: digest, CSRDER: base64.RawStdEncoding.EncodeToString(csrDER),
		Nonce: hex.EncodeToString(nonce), Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(identity.privateKey, message))}
	encoded, err := json.Marshal(state)
	if err != nil || replaceFileSync(path, append(encoded, '\n')) != nil || syncDirectory(recoverer.config.IdentityDir) != nil {
		return recoveryState{}, fmt.Errorf("%w: persist recovery request", ErrPersistence)
	}
	return state, nil
}

func recoveryRequest(state recoveryState, identity renewalIdentity) (*agentv1.RecoverCertificateRequest, error) {
	sent, sentErr := time.Parse(time.RFC3339Nano, state.SentTime)
	csr, csrErr := base64.RawStdEncoding.DecodeString(state.CSRDER)
	nonce, nonceErr := hex.DecodeString(state.Nonce)
	signature, signatureErr := base64.RawStdEncoding.DecodeString(state.Signature)
	if sentErr != nil || csrErr != nil || nonceErr != nil || signatureErr != nil || len(nonce) != 32 ||
		!ed25519.Verify(identity.privateKey.Public().(ed25519.PublicKey),
			RecoveryMessage(state.RequestID, sent, identity.state.NodeID, identity.leaf.Raw, csr, nonce), signature) {
		return nil, fmt.Errorf("%w: recovery state is invalid", ErrRecoveryState)
	}
	return &agentv1.RecoverCertificateRequest{
		Request: &commonv1.RequestMetadata{RequestId: state.RequestID, SentTime: timestamppb.New(sent), CorrelationId: state.RequestID},
		NodeId:  identity.state.NodeID, ExpiredCertificateDer: bytes.Clone(identity.leaf.Raw),
		CertificateSigningRequestDer: csr, Nonce: nonce, Signature: signature,
	}, nil
}
