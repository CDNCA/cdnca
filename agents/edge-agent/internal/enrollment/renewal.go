package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	renewalStateFileName        = "renewal.json"
	renewalErrorDomain          = "cdnca.com/node-certificate-renewal"
	renewalReasonTooEarly       = "renewal_too_early"
	renewalReasonRequestExpired = "renewal_request_expired"
)

var ErrRenewalRejected = errors.New("gateway certificate renewal failed")

type RenewalRPC interface {
	RenewCertificate(context.Context, *agentv1.RenewCertificateRequest, ...grpc.CallOption) (*agentv1.RenewCertificateResponse, error)
}

type Renewer struct {
	identityDir string
	now         func() time.Time
	random      io.Reader
	mu          sync.Mutex
	retryAfter  time.Time
}

type renewalState struct {
	Version                  int    `json:"version"`
	RequestID                string `json:"request_id"`
	CurrentSerialNumber      string `json:"current_serial_number"`
	CurrentCertificateSHA256 string `json:"current_certificate_sha256"`
	CSRDER                   string `json:"certificate_signing_request_der"`
}

type renewalIdentity struct {
	state          identityState
	privateKey     ed25519.PrivateKey
	certificatePEM []byte
	leaf           *x509.Certificate
	root           *x509.Certificate
	digest         [sha256.Size]byte
}

type renewalRetryDirective struct {
	reason  string
	retryAt time.Time
}

func NewRenewer(identityDir string) (*Renewer, error) {
	if validateSecureDirectory(identityDir) != nil {
		return nil, fmt.Errorf("%w: renewal identity directory is unsafe", ErrInvalidInput)
	}
	return &Renewer{identityDir: identityDir, now: time.Now, random: rand.Reader}, nil
}

func (renewer *Renewer) Renew(ctx context.Context, gateway agentv1.AgentGatewayServiceClient) (bool, string, error) {
	return renewer.renew(ctx, gateway)
}

func (renewer *Renewer) renew(ctx context.Context, gateway RenewalRPC) (bool, string, error) {
	if renewer == nil || ctx == nil || gateway == nil || renewer.now == nil || renewer.random == nil {
		return false, "", fmt.Errorf("%w: certificate renewer is incomplete", ErrInvalidInput)
	}
	renewer.mu.Lock()
	defer renewer.mu.Unlock()

	now := renewer.now().UTC().Truncate(time.Second)
	identity, err := loadRenewalIdentity(renewer.identityDir, now)
	if err != nil {
		return false, "", err
	}
	if now.Before(identity.leaf.NotBefore.Add(identity.leaf.NotAfter.Sub(identity.leaf.NotBefore)/2)) || now.Before(renewer.retryAfter) {
		return false, "", nil
	}

	state, err := renewer.loadOrCreateState(identity)
	if err != nil {
		return false, "", err
	}
	response, err := gateway.RenewCertificate(ctx, &agentv1.RenewCertificateRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: state.RequestID, SentTime: timestamppb.New(now), CorrelationId: state.RequestID,
		},
		CurrentSerialNumber:          state.CurrentSerialNumber,
		CertificateSigningRequestDer: mustDecodeRenewalCSR(state.CSRDER),
	}, grpc.WaitForReady(false))
	if err != nil {
		if directive, ok := parseRenewalRetryDirective(err); ok {
			if now.Before(directive.retryAt) {
				renewer.retryAfter = directive.retryAt
				return false, "", nil
			}
			if directive.reason == renewalReasonRequestExpired {
				if err := renewer.rotateExpiredState(state, identity, renewer.now().UTC().Truncate(time.Second)); err != nil {
					return false, "", err
				}
				renewer.retryAfter = time.Time{}
				return false, "", nil
			}
			renewer.retryAfter = now.Add(5 * time.Minute)
			return false, "", nil
		}
		if status.Code(err) == codes.FailedPrecondition {
			renewer.retryAfter = now.Add(5 * time.Minute)
			return false, "", nil
		}
		renewer.retryAfter = now.Add(30 * time.Second)
		return false, "", fmt.Errorf("%w: request rejected", ErrRenewalRejected)
	}
	certificatePEM, certificateSHA, err := validateRenewalResponse(response, identity, now)
	if err != nil {
		return false, "", err
	}
	certificatePath := filepath.Join(renewer.identityDir, clientCertFileName)
	if err := replaceRenewedCertificate(certificatePath, renewer.identityDir, certificatePEM, identity.certificatePEM, now); err != nil {
		return false, "", err
	}
	statePath := filepath.Join(renewer.identityDir, renewalStateFileName)
	if err := os.Remove(statePath); err == nil {
		_ = syncDirectory(renewer.identityDir)
	}
	renewer.retryAfter = time.Time{}
	return true, certificateSHA, nil
}

func loadRenewalIdentity(directory string, now time.Time) (renewalIdentity, error) {
	state, artifactKey, err := loadIdentity(directory, now)
	clear(artifactKey)
	if err != nil {
		return renewalIdentity{}, err
	}
	return loadRenewalKeyPair(directory, state)
}

// loadRenewalKeyPair reads the key pair of an identity loadIdentity verified.
func loadRenewalKeyPair(directory string, state identityState) (renewalIdentity, error) {
	certificatePEM, err := readRegular(filepath.Join(directory, clientCertFileName), maxSecurityFile, true)
	if err != nil {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	privatePEM, err := readRegular(filepath.Join(directory, clientKeyFileName), maxSecurityFile, true)
	if err != nil {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	pair, err := tls.X509KeyPair(certificatePEM, privatePEM)
	clear(privatePEM)
	if err != nil || len(pair.Certificate) < 2 {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	privateKey, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	root, err := x509.ParseCertificate(pair.Certificate[len(pair.Certificate)-1])
	if err != nil {
		return renewalIdentity{}, ErrInvalidIdentity
	}
	return renewalIdentity{
		state: state, privateKey: privateKey, certificatePEM: certificatePEM,
		leaf: leaf, root: root, digest: sha256.Sum256(leaf.Raw),
	}, nil
}

func (renewer *Renewer) loadOrCreateState(identity renewalIdentity) (renewalState, error) {
	statePath := filepath.Join(renewer.identityDir, renewalStateFileName)
	if exists(statePath) {
		content, err := readRegular(statePath, maxSecurityFile, true)
		if err != nil {
			return renewalState{}, fmt.Errorf("%w: renewal state is unreadable", ErrRecoveryState)
		}
		state, err := decodeRenewalState(content)
		if err != nil {
			return renewalState{}, err
		}
		if renewalStateMatchesIdentity(state, identity) {
			return state, nil
		}
		if err := os.Remove(statePath); err != nil || syncDirectory(renewer.identityDir) != nil {
			return renewalState{}, fmt.Errorf("%w: clear completed renewal state", ErrPersistence)
		}
	}
	state, err := renewer.createState(identity)
	if err != nil {
		return renewalState{}, err
	}
	if err := persistRenewalState(statePath, renewer.identityDir, state); err != nil {
		return renewalState{}, err
	}
	return state, nil
}

func (renewer *Renewer) createState(identity renewalIdentity) (renewalState, error) {
	requestID, err := uuid.NewRandomFromReader(renewer.random)
	if err != nil {
		return renewalState{}, fmt.Errorf("%w: create renewal request ID", ErrPersistence)
	}
	csrDER, err := x509.CreateCertificateRequest(renewer.random, &x509.CertificateRequest{
		Subject: pkix.Name{SerialNumber: requestID.String()},
	}, identity.privateKey)
	if err != nil {
		return renewalState{}, fmt.Errorf("%w: create renewal CSR", ErrPersistence)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	publicKey, ok := csrPublicKey(csr)
	if err != nil || csr.CheckSignature() != nil || !ok || !bytes.Equal(publicKey, identity.privateKey.Public().(ed25519.PublicKey)) ||
		len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return renewalState{}, fmt.Errorf("%w: generated renewal CSR is invalid", ErrPersistence)
	}
	state := renewalState{
		Version: 1, RequestID: requestID.String(),
		CurrentSerialNumber:      strings.ToLower(identity.leaf.SerialNumber.Text(16)),
		CurrentCertificateSHA256: hex.EncodeToString(identity.digest[:]),
		CSRDER:                   base64.RawStdEncoding.EncodeToString(csrDER),
	}
	return state, nil
}

func persistRenewalState(path, directory string, state renewalState) error {
	encoded, err := json.Marshal(state)
	if err != nil || replaceFileSync(path, append(encoded, '\n')) != nil || syncDirectory(directory) != nil {
		return fmt.Errorf("%w: persist renewal request", ErrPersistence)
	}
	return nil
}

func renewalStateMatchesIdentity(state renewalState, identity renewalIdentity) bool {
	if state.CurrentSerialNumber != strings.ToLower(identity.leaf.SerialNumber.Text(16)) ||
		state.CurrentCertificateSHA256 != hex.EncodeToString(identity.digest[:]) {
		return false
	}
	csrDER, err := base64.RawStdEncoding.DecodeString(state.CSRDER)
	csr, parseErr := x509.ParseCertificateRequest(csrDER)
	publicKey, ok := csrPublicKey(csr)
	return err == nil && parseErr == nil && csr.CheckSignature() == nil && ok &&
		(csr.Subject.SerialNumber == "" || csr.Subject.SerialNumber == state.RequestID) &&
		bytes.Equal(publicKey, identity.privateKey.Public().(ed25519.PublicKey))
}

func (renewer *Renewer) rotateExpiredState(expected renewalState, observed renewalIdentity, now time.Time) error {
	current, err := loadRenewalIdentity(renewer.identityDir, now)
	if err != nil {
		return err
	}
	if current.state.NodeID != observed.state.NodeID || !bytes.Equal(current.leaf.Raw, observed.leaf.Raw) ||
		!renewalStateMatchesIdentity(expected, current) {
		return fmt.Errorf("%w: renewal identity changed before request rotation", ErrRecoveryState)
	}
	path := filepath.Join(renewer.identityDir, renewalStateFileName)
	content, err := readRegular(path, maxSecurityFile, true)
	if err != nil {
		return fmt.Errorf("%w: renewal state is unreadable", ErrRecoveryState)
	}
	stored, err := decodeRenewalState(content)
	if err != nil {
		return err
	}
	if stored != expected || !renewalStateMatchesIdentity(stored, current) {
		return fmt.Errorf("%w: renewal state changed before request rotation", ErrRecoveryState)
	}
	replacement, err := renewer.createState(current)
	if err != nil {
		return err
	}
	if replacement.RequestID == stored.RequestID || replacement.CSRDER == stored.CSRDER {
		return fmt.Errorf("%w: replacement renewal request was not unique", ErrPersistence)
	}
	return persistRenewalState(path, renewer.identityDir, replacement)
}

func parseRenewalRetryDirective(err error) (renewalRetryDirective, bool) {
	converted, ok := status.FromError(err)
	if !ok || converted.Code() != codes.FailedPrecondition {
		return renewalRetryDirective{}, false
	}
	var result renewalRetryDirective
	found := false
	for _, detail := range converted.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || info.GetDomain() != renewalErrorDomain {
			continue
		}
		if found || (info.GetReason() != renewalReasonTooEarly && info.GetReason() != renewalReasonRequestExpired) {
			return renewalRetryDirective{}, false
		}
		retryAtText := info.GetMetadata()["retry_at"]
		retryAt, parseErr := time.Parse(time.RFC3339, retryAtText)
		if parseErr != nil || retryAt.IsZero() || retryAt.Nanosecond() != 0 ||
			retryAtText != retryAt.UTC().Format(time.RFC3339) {
			return renewalRetryDirective{}, false
		}
		result = renewalRetryDirective{reason: info.GetReason(), retryAt: retryAt.UTC()}
		found = true
	}
	return result, found
}

func decodeRenewalState(content []byte) (renewalState, error) {
	var state renewalState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Version != 1 ||
		!canonicalUUID(state.RequestID) || state.CurrentSerialNumber == "" ||
		state.CurrentSerialNumber != strings.ToLower(state.CurrentSerialNumber) {
		return renewalState{}, fmt.Errorf("%w: renewal metadata is invalid", ErrRecoveryState)
	}
	digest, err := hex.DecodeString(state.CurrentCertificateSHA256)
	if err != nil || len(digest) != sha256.Size || state.CurrentCertificateSHA256 != hex.EncodeToString(digest) {
		return renewalState{}, fmt.Errorf("%w: renewal certificate digest is invalid", ErrRecoveryState)
	}
	csrDER, err := base64.RawStdEncoding.DecodeString(state.CSRDER)
	csr, parseErr := x509.ParseCertificateRequest(csrDER)
	if err != nil || parseErr != nil || csr.CheckSignature() != nil ||
		(csr.Subject.SerialNumber != "" && csr.Subject.SerialNumber != state.RequestID) ||
		len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return renewalState{}, fmt.Errorf("%w: renewal CSR is invalid", ErrRecoveryState)
	}
	if _, ok := csrPublicKey(csr); !ok {
		return renewalState{}, fmt.Errorf("%w: renewal CSR key is invalid", ErrRecoveryState)
	}
	return state, nil
}

func mustDecodeRenewalCSR(value string) []byte {
	decoded, _ := base64.RawStdEncoding.DecodeString(value)
	return decoded
}

func validateRenewalResponse(response *agentv1.RenewCertificateResponse, current renewalIdentity, now time.Time) ([]byte, string, error) {
	if response == nil || hasUnknown(response.ProtoReflect()) || response.Certificate == nil || hasUnknown(response.Certificate.ProtoReflect()) {
		return nil, "", ErrInvalidResponse
	}
	bundle := response.Certificate
	leaf, err := parseCertificate(bundle.LeafCertificatePem)
	if err != nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != nodeSPIFFEPrefix+current.state.NodeID ||
		len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
		return nil, "", ErrInvalidResponse
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, current.privateKey.Public().(ed25519.PublicKey)) || !bytes.Equal(publicKey, current.leaf.PublicKey.(ed25519.PublicKey)) {
		return nil, "", ErrInvalidResponse
	}
	if bundle.NotBeforeTime == nil || bundle.ExpirationTime == nil || bundle.RenewalTime == nil ||
		bundle.NotBeforeTime.CheckValid() != nil || bundle.ExpirationTime.CheckValid() != nil || bundle.RenewalTime.CheckValid() != nil ||
		hasUnknown(bundle.NotBeforeTime.ProtoReflect()) || hasUnknown(bundle.ExpirationTime.ProtoReflect()) || hasUnknown(bundle.RenewalTime.ProtoReflect()) {
		return nil, "", ErrInvalidResponse
	}
	notBefore, notAfter, renewalAt := bundle.NotBeforeTime.AsTime(), bundle.ExpirationTime.AsTime(), bundle.RenewalTime.AsTime()
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	if bundle.SerialNumber == "" || bundle.SerialNumber != serial || serial == strings.ToLower(current.leaf.SerialNumber.Text(16)) ||
		!leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) || !renewalAt.After(notBefore) || !renewalAt.Before(notAfter) ||
		now.Before(notBefore) || !now.Before(notAfter) || !notAfter.After(current.leaf.NotAfter) {
		return nil, "", ErrInvalidResponse
	}
	if len(bundle.IssuingChainPem) == 0 || len(bundle.IssuingChainPem) > 8 {
		return nil, "", ErrInvalidResponse
	}
	chain := make([]*x509.Certificate, len(bundle.IssuingChainPem))
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	for index, encoded := range bundle.IssuingChainPem {
		chain[index], err = parseCertificate(encoded)
		if err != nil || !chain[index].IsCA || !chain[index].BasicConstraintsValid || chain[index].KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, "", ErrInvalidResponse
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[index].Raw})...)
	}
	if !bytes.Equal(chain[len(chain)-1].Raw, current.root.Raw) || leaf.CheckSignatureFrom(chain[0]) != nil {
		return nil, "", ErrInvalidResponse
	}
	for index := 0; index < len(chain)-1; index++ {
		if chain[index].CheckSignatureFrom(chain[index+1]) != nil {
			return nil, "", ErrInvalidResponse
		}
	}
	if current.root.CheckSignatureFrom(current.root) != nil {
		return nil, "", ErrInvalidResponse
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(current.root)
	for _, certificate := range chain[:len(chain)-1] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, "", ErrInvalidResponse
	}
	digest := sha256.Sum256(leaf.Raw)
	return certificatePEM, hex.EncodeToString(digest[:]), nil
}

func replaceRenewedCertificate(path, directory string, renewed, previous []byte, now time.Time) error {
	if err := replaceFileSync(path, renewed); err != nil {
		return fmt.Errorf("%w: replace client certificate", ErrPersistence)
	}
	restore := func(cause error) error {
		restoreErr := replaceFileSync(path, previous)
		if restoreErr == nil {
			restoreErr = syncDirectory(directory)
		}
		if restoreErr != nil {
			return fmt.Errorf("%w: %v; restore previous certificate: %v", ErrPersistence, cause, restoreErr)
		}
		return fmt.Errorf("%w: %v", ErrPersistence, cause)
	}
	if err := syncDirectory(directory); err != nil {
		return restore(err)
	}
	_, artifactKey, err := loadIdentity(directory, now)
	clear(artifactKey)
	if err != nil {
		return restore(err)
	}
	return nil
}
