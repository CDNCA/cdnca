package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	pendingSuffix       = ".enrolling"
	lockSuffix          = ".enroll.lock"
	pendingFileName     = "pending.json"
	identityFileName    = "identity.json"
	clientCertFileName  = "client.pem"
	clientKeyFileName   = "client-key.pem"
	artifactKeyFileName = "artifact-x25519-key.bin"
	maxTokenBytes       = 1024
	maxMachineIDBytes   = 4096
	maxSecurityFile     = 1 << 20
	nodeSPIFFEPrefix    = "spiffe://cdn-platform/node/"
)

var (
	ErrInvalidInput       = errors.New("invalid enrollment input")
	ErrAlreadyEnrolled    = errors.New("edge agent identity already exists")
	ErrEnrollmentBusy     = errors.New("edge agent enrollment is already running")
	ErrInvalidResponse    = errors.New("invalid enrollment response")
	ErrPersistence        = errors.New("persist edge agent identity")
	ErrRecoveryState      = errors.New("invalid enrollment recovery state")
	ErrEnrollmentRejected = errors.New("gateway enrollment failed")
	ErrInvalidIdentity    = errors.New("invalid edge agent identity")
)

type Config struct {
	Address    string
	ServerName string
	RootCAFile string
	// Transport "ws" enrolls through the gateway tunnel /agent/v1/enroll
	// at Address (CDN entrance); TunnelHost is the outer SNI/Host.
	Transport         string
	TunnelHost        string
	IdentityDir       string
	MachineIDFile     string
	SupportedVersions *commonv1.ProtocolVersionRange
	Capabilities      *agentv1.AgentCapabilities
	Now               func() time.Time
	Random            io.Reader
	Dial              func(context.Context, Config) (RPC, io.Closer, error)
}

type RPC interface {
	Enroll(context.Context, *agentv1.EnrollRequest, ...grpc.CallOption) (*agentv1.EnrollResponse, error)
}

type Result struct {
	NodeID                  string `json:"node_id"`
	ProtocolMajor           uint32 `json:"protocol_major"`
	ProtocolMinor           uint32 `json:"protocol_minor"`
	ArtifactEncryptionKeyID string `json:"artifact_encryption_key_id"`
	IdentityFile            string `json:"identity_file"`
	ClientCertificateFile   string `json:"client_certificate_file"`
	ClientPrivateKeyFile    string `json:"client_private_key_file"`
	ArtifactPrivateKeyFile  string `json:"artifact_encryption_private_key_file"`
}

type Identity struct {
	NodeID string
	// CertificateExpired is set by LoadIdentityAllowingExpired when the client
	// certificate is past NotAfter: the agent must recover it (RecoverCertificate)
	// before it can connect.
	CertificateExpired           bool
	ProtocolMajor                uint32
	ProtocolMinor                uint32
	ArtifactEncryptionKeyID      string
	ClientCertificateFile        string
	ClientPrivateKeyFile         string
	ArtifactPrivateKeyFile       string
	ArtifactEncryptionPrivateKey []byte
}

type pendingState struct {
	Version                  int    `json:"version"`
	RequestID                string `json:"request_id"`
	MachineFingerprintSHA256 string `json:"machine_fingerprint_sha256"`
	CSRDER                   string `json:"certificate_signing_request_der"`
	ClientPrivateKeyPKCS8    string `json:"client_private_key_pkcs8"`
	ArtifactPrivateKey       string `json:"artifact_x25519_private_key"`
}

type identityState struct {
	Version                          int    `json:"version"`
	NodeID                           string `json:"node_id"`
	MachineFingerprintSHA256         string `json:"machine_fingerprint_sha256"`
	SelectedProtocolMajor            uint32 `json:"selected_protocol_major"`
	SelectedProtocolMinor            uint32 `json:"selected_protocol_minor"`
	ArtifactEncryptionKeyID          string `json:"artifact_encryption_key_id"`
	ClientCertificateFile            string `json:"client_certificate_file"`
	ClientPrivateKeyFile             string `json:"client_private_key_file"`
	ArtifactEncryptionPrivateKeyFile string `json:"artifact_encryption_private_key_file"`
}

type preparedEnrollment struct {
	state       pendingState
	privateKey  ed25519.PrivateKey
	csrDER      []byte
	artifactKey *ecdh.PrivateKey
	fingerprint []byte
}

func Run(ctx context.Context, config Config, token []byte) (Result, error) {
	config = withDefaults(config)
	if err := validateConfig(config); err != nil {
		return Result{}, err
	}
	parsedToken, err := validateToken(token)
	if err != nil {
		return Result{}, err
	}
	defer clear(parsedToken)
	fingerprint, err := MachineFingerprint(config.MachineIDFile)
	if err != nil {
		return Result{}, err
	}
	lock, err := acquireLock(config.IdentityDir)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	if exists(config.IdentityDir) {
		return Result{}, ErrAlreadyEnrolled
	}
	pendingDir := config.IdentityDir + pendingSuffix
	if complete, result := completedPending(pendingDir, fingerprint); complete {
		if err := commitPending(pendingDir, config.IdentityDir); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	prepared, err := prepare(pendingDir, fingerprint, config.Random)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(prepared.fingerprint, fingerprint) {
		return Result{}, fmt.Errorf("%w: machine identity changed", ErrRecoveryState)
	}
	request := &agentv1.EnrollRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: prepared.state.RequestID, SentTime: timestamppb.New(config.Now().UTC()),
			CorrelationId: prepared.state.RequestID,
		},
		EnrollmentToken:              string(parsedToken),
		CertificateSigningRequestDer: bytes.Clone(prepared.csrDER),
		MachineFingerprintSha256:     bytes.Clone(prepared.fingerprint),
		SupportedProtocolVersions:    proto.Clone(config.SupportedVersions).(*commonv1.ProtocolVersionRange),
		Capabilities:                 proto.Clone(config.Capabilities).(*agentv1.AgentCapabilities),
		ArtifactEncryptionPublicKey:  prepared.artifactKey.PublicKey().Bytes(),
	}
	defer func() { request.EnrollmentToken = "" }()
	rpc, closer, err := config.Dial(ctx, config)
	if err != nil {
		return Result{}, fmt.Errorf("%w: connect to enrollment endpoint", ErrEnrollmentRejected)
	}
	if rpc == nil {
		return Result{}, fmt.Errorf("%w: enrollment endpoint unavailable", ErrEnrollmentRejected)
	}
	if closer != nil {
		defer closer.Close()
	}
	response, err := rpc.Enroll(ctx, request, grpc.WaitForReady(false))
	if err != nil {
		return Result{}, fmt.Errorf("%w: request rejected", ErrEnrollmentRejected)
	}
	identity, certificatePEM, err := validateResponse(response, config.SupportedVersions, prepared.privateKey.Public().(ed25519.PublicKey), prepared.artifactKey, config.Now())
	if err != nil {
		return Result{}, err
	}
	identity.MachineFingerprintSHA256 = base64.RawStdEncoding.EncodeToString(prepared.fingerprint)
	privateDER, err := x509.MarshalPKCS8PrivateKey(prepared.privateKey)
	if err != nil {
		return Result{}, fmt.Errorf("%w: encode client private key", ErrPersistence)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := writeFinalFiles(pendingDir, identity, certificatePEM, privatePEM, prepared.artifactKey.Bytes()); err != nil {
		return Result{}, err
	}
	clear(privateDER)
	clear(privatePEM)
	if err := commitPending(pendingDir, config.IdentityDir); err != nil {
		return Result{}, err
	}
	return resultFor(config.IdentityDir, identity), nil
}

func ReadToken(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: enrollment token input is required", ErrInvalidInput)
	}
	value, err := io.ReadAll(io.LimitReader(reader, maxTokenBytes+1))
	if err != nil || len(value) > maxTokenBytes {
		return nil, fmt.Errorf("%w: enrollment token exceeds its size limit", ErrInvalidInput)
	}
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
		if len(value) > 0 && value[len(value)-1] == '\r' {
			value = value[:len(value)-1]
		}
	}
	if bytes.ContainsAny(value, "\r\n\t ") {
		clear(value)
		return nil, fmt.Errorf("%w: enrollment token must be one exact line", ErrInvalidInput)
	}
	token, err := validateToken(value)
	clear(value)
	return token, err
}

func ReadTokenFile(path string) ([]byte, error) {
	value, err := readRegular(path, maxTokenBytes, true)
	if err != nil {
		return nil, fmt.Errorf("%w: enrollment token file is unsafe", ErrInvalidInput)
	}
	token, tokenErr := ReadToken(bytes.NewReader(value))
	clear(value)
	return token, tokenErr
}

func MachineFingerprint(path string) ([]byte, error) {
	value, err := readRegular(path, maxMachineIDBytes, false)
	if err != nil {
		return nil, fmt.Errorf("%w: machine ID file is unsafe", ErrInvalidInput)
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.IndexByte(trimmed, 0) >= 0 || bytes.ContainsAny(trimmed, "\r\n") {
		clear(value)
		return nil, fmt.Errorf("%w: machine ID is invalid", ErrInvalidInput)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("cdnca-machine-fingerprint-v1\x00"))
	_, _ = hasher.Write(trimmed)
	result := hasher.Sum(nil)
	clear(value)
	return result, nil
}

func Dial(ctx context.Context, config Config) (RPC, io.Closer, error) {
	rootPEM, err := readRegular(config.RootCAFile, maxSecurityFile, false)
	if err != nil {
		return nil, nil, fmt.Errorf("load gateway root CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, nil, fmt.Errorf("gateway root CA contains no certificate")
	}
	target := config.Address
	options := []grpc.DialOption{}
	switch config.Transport {
	case "", gatewaytunnel.TransportGRPC:
	case gatewaytunnel.TransportWS:
		target = "passthrough:///" + config.Address
		options = append(options, grpc.WithContextDialer(gatewaytunnel.EnrollmentTunnel(config.Address, config.TunnelHost, rootPEM)))
	default:
		return nil, nil, fmt.Errorf("gateway transport must be grpc or ws")
	}
	connection, err := grpc.DialContext(ctx, target, append(options,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: config.ServerName, RootCAs: roots,
		})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxSecurityFile), grpc.MaxCallSendMsgSize(maxSecurityFile)),
	)...)
	if err != nil {
		return nil, nil, err
	}
	return agentv1.NewAgentGatewayServiceClient(connection), connection, nil
}

func withDefaults(config Config) Config {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Dial == nil {
		config.Dial = Dial
	}
	return config
}

func validateConfig(config Config) error {
	if strings.TrimSpace(config.Address) != config.Address || strings.Contains(config.Address, "://") {
		return fmt.Errorf("%w: gateway address must be host:port", ErrInvalidInput)
	}
	host, port, err := net.SplitHostPort(config.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || portNumber == 0 || strings.TrimSpace(config.ServerName) != config.ServerName || config.ServerName == "" || len(config.ServerName) > 253 {
		return fmt.Errorf("%w: gateway address and server name are required", ErrInvalidInput)
	}
	for _, path := range []string{config.RootCAFile, config.IdentityDir, config.MachineIDFile} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return fmt.Errorf("%w: enrollment paths must be absolute and clean", ErrInvalidInput)
		}
	}
	if err := validateVersionRange(config.SupportedVersions); err != nil || config.Capabilities == nil || config.Capabilities.AgentVersion == "" || config.Capabilities.BuildId == "" || config.Capabilities.OperatingSystem == "" || config.Capabilities.Architecture == "" {
		return fmt.Errorf("%w: protocol versions and capabilities are required", ErrInvalidInput)
	}
	if config.Now == nil || config.Random == nil || config.Dial == nil {
		return fmt.Errorf("%w: enrollment dependencies are required", ErrInvalidInput)
	}
	return validateSecureDirectory(filepath.Dir(config.IdentityDir))
}

func validateToken(value []byte) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(value))
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != string(value) {
		clear(decoded)
		return nil, fmt.Errorf("%w: enrollment token format is invalid", ErrInvalidInput)
	}
	clear(decoded)
	return bytes.Clone(value), nil
}

func prepare(directory string, fingerprint []byte, random io.Reader) (preparedEnrollment, error) {
	statePath := filepath.Join(directory, pendingFileName)
	if exists(directory) {
		if err := validateSecureDirectory(directory); err != nil {
			return preparedEnrollment{}, fmt.Errorf("%w: %v", ErrRecoveryState, err)
		}
		if exists(statePath) {
			content, err := readRegular(statePath, maxSecurityFile, true)
			if err != nil {
				return preparedEnrollment{}, fmt.Errorf("%w: pending state is incomplete", ErrRecoveryState)
			}
			return decodePending(content)
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return preparedEnrollment{}, fmt.Errorf("%w: inspect pending state", ErrRecoveryState)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmp") {
				return preparedEnrollment{}, fmt.Errorf("%w: pending state is incomplete", ErrRecoveryState)
			}
		}
		if err := os.RemoveAll(directory); err != nil {
			return preparedEnrollment{}, fmt.Errorf("%w: reset incomplete pending state", ErrPersistence)
		}
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: create recovery directory", ErrPersistence)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return preparedEnrollment{}, fmt.Errorf("%w: secure recovery directory", ErrPersistence)
	}
	created := true
	defer func() {
		if created {
			_ = os.RemoveAll(directory)
		}
	}()
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: generate client key", ErrPersistence)
	}
	csrDER, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: generate certificate request", ErrPersistence)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	csrPublic, csrIsEd25519 := csrPublicKey(csr)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 || !csrIsEd25519 || !bytes.Equal(csrPublic, publicKey) {
		return preparedEnrollment{}, fmt.Errorf("%w: generated certificate request is invalid", ErrPersistence)
	}
	artifactKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: generate artifact key", ErrPersistence)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: encode client key", ErrPersistence)
	}
	state := pendingState{
		Version: 1, RequestID: uuid.NewString(),
		MachineFingerprintSHA256: base64.RawStdEncoding.EncodeToString(fingerprint),
		CSRDER:                   base64.RawStdEncoding.EncodeToString(csrDER),
		ClientPrivateKeyPKCS8:    base64.RawStdEncoding.EncodeToString(privateDER),
		ArtifactPrivateKey:       base64.RawStdEncoding.EncodeToString(artifactKey.Bytes()),
	}
	encoded, err := json.Marshal(state)
	clear(privateDER)
	if err != nil || replaceFileSync(statePath, encoded) != nil || syncDirectory(directory) != nil || syncDirectory(filepath.Dir(directory)) != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: write recovery state", ErrPersistence)
	}
	created = false
	return preparedEnrollment{state: state, privateKey: privateKey, csrDER: csrDER, artifactKey: artifactKey, fingerprint: bytes.Clone(fingerprint)}, nil
}

func decodePending(content []byte) (preparedEnrollment, error) {
	var state pendingState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Version != 1 || !canonicalUUID(state.RequestID) {
		return preparedEnrollment{}, fmt.Errorf("%w: pending metadata is invalid", ErrRecoveryState)
	}
	fingerprint, err := base64.RawStdEncoding.DecodeString(state.MachineFingerprintSHA256)
	if err != nil || len(fingerprint) != sha256.Size {
		return preparedEnrollment{}, fmt.Errorf("%w: pending fingerprint is invalid", ErrRecoveryState)
	}
	csrDER, err := base64.RawStdEncoding.DecodeString(state.CSRDER)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: pending CSR is invalid", ErrRecoveryState)
	}
	privateDER, err := base64.RawStdEncoding.DecodeString(state.ClientPrivateKeyPKCS8)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: pending client key is invalid", ErrRecoveryState)
	}
	parsedPrivate, err := x509.ParsePKCS8PrivateKey(privateDER)
	clear(privateDER)
	privateKey, ok := parsedPrivate.(ed25519.PrivateKey)
	if err != nil || !ok || len(privateKey) != ed25519.PrivateKeySize {
		return preparedEnrollment{}, fmt.Errorf("%w: pending client key is invalid", ErrRecoveryState)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	csrPublic, csrIsEd25519 := csrPublicKey(csr)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 || !csrIsEd25519 || !bytes.Equal(csrPublic, privateKey.Public().(ed25519.PublicKey)) {
		return preparedEnrollment{}, fmt.Errorf("%w: pending CSR binding is invalid", ErrRecoveryState)
	}
	artifactBytes, err := base64.RawStdEncoding.DecodeString(state.ArtifactPrivateKey)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: pending artifact key is invalid", ErrRecoveryState)
	}
	artifactKey, err := ecdh.X25519().NewPrivateKey(artifactBytes)
	clear(artifactBytes)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: pending artifact key is invalid", ErrRecoveryState)
	}
	return preparedEnrollment{state: state, privateKey: privateKey, csrDER: csrDER, artifactKey: artifactKey, fingerprint: fingerprint}, nil
}

func validateResponse(response *agentv1.EnrollResponse, supported *commonv1.ProtocolVersionRange, publicKey ed25519.PublicKey, artifactKey *ecdh.PrivateKey, now time.Time) (identityState, []byte, error) {
	if response == nil || hasUnknown(response.ProtoReflect()) || !canonicalUUID(response.NodeId) || !versionInRange(response.SelectedProtocolVersion, supported) || response.Certificate == nil || hasUnknown(response.Certificate.ProtoReflect()) {
		return identityState{}, nil, ErrInvalidResponse
	}
	digest := sha256.Sum256(artifactKey.PublicKey().Bytes())
	expectedKeyID := "x25519:" + hex.EncodeToString(digest[:])
	if response.ArtifactEncryptionKeyId != expectedKeyID {
		return identityState{}, nil, ErrInvalidResponse
	}
	leaf, err := parseCertificate(response.Certificate.LeafCertificatePem)
	if err != nil || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
		return identityState{}, nil, ErrInvalidResponse
	}
	expectedURI, _ := url.Parse(nodeSPIFFEPrefix + response.NodeId)
	leafPublic, leafIsEd25519 := leaf.PublicKey.(ed25519.PublicKey)
	if leaf.URIs[0].String() != expectedURI.String() || !leafIsEd25519 || !bytes.Equal(leafPublic, publicKey) {
		return identityState{}, nil, ErrInvalidResponse
	}
	bundle := response.Certificate
	if bundle.NotBeforeTime == nil || bundle.ExpirationTime == nil || bundle.RenewalTime == nil || bundle.NotBeforeTime.CheckValid() != nil || bundle.ExpirationTime.CheckValid() != nil || bundle.RenewalTime.CheckValid() != nil || hasUnknown(bundle.NotBeforeTime.ProtoReflect()) || hasUnknown(bundle.ExpirationTime.ProtoReflect()) || hasUnknown(bundle.RenewalTime.ProtoReflect()) {
		return identityState{}, nil, ErrInvalidResponse
	}
	notBefore, expiration, renewal := bundle.NotBeforeTime.AsTime(), bundle.ExpirationTime.AsTime(), bundle.RenewalTime.AsTime()
	if !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(expiration) || !renewal.After(notBefore) || !renewal.Before(expiration) || now.Before(notBefore) || !now.Before(expiration) || bundle.SerialNumber == "" || strings.ToLower(leaf.SerialNumber.Text(16)) != bundle.SerialNumber {
		return identityState{}, nil, ErrInvalidResponse
	}
	if len(bundle.IssuingChainPem) == 0 || len(bundle.IssuingChainPem) > 8 {
		return identityState{}, nil, ErrInvalidResponse
	}
	chain := make([]*x509.Certificate, len(bundle.IssuingChainPem))
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	for index, encoded := range bundle.IssuingChainPem {
		chain[index], err = parseCertificate(encoded)
		if err != nil || !chain[index].IsCA || !chain[index].BasicConstraintsValid || chain[index].KeyUsage&x509.KeyUsageCertSign == 0 {
			return identityState{}, nil, ErrInvalidResponse
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[index].Raw})...)
	}
	if leaf.CheckSignatureFrom(chain[0]) != nil {
		return identityState{}, nil, ErrInvalidResponse
	}
	for index := 0; index < len(chain)-1; index++ {
		if chain[index].CheckSignatureFrom(chain[index+1]) != nil {
			return identityState{}, nil, ErrInvalidResponse
		}
	}
	root := chain[len(chain)-1]
	if root.CheckSignatureFrom(root) != nil {
		return identityState{}, nil, ErrInvalidResponse
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, certificate := range chain[:len(chain)-1] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return identityState{}, nil, ErrInvalidResponse
	}
	return identityState{
		Version: 1, NodeID: response.NodeId,
		SelectedProtocolMajor:   response.SelectedProtocolVersion.Major,
		SelectedProtocolMinor:   response.SelectedProtocolVersion.Minor,
		ArtifactEncryptionKeyID: response.ArtifactEncryptionKeyId,
		ClientCertificateFile:   clientCertFileName, ClientPrivateKeyFile: clientKeyFileName,
		ArtifactEncryptionPrivateKeyFile: artifactKeyFileName,
	}, certificatePEM, nil
}

func writeFinalFiles(directory string, identity identityState, certificatePEM, privatePEM, artifactKey []byte) error {
	encoded, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("%w: encode identity metadata", ErrPersistence)
	}
	for name, value := range map[string][]byte{
		clientCertFileName: certificatePEM, clientKeyFileName: privatePEM,
		artifactKeyFileName: artifactKey, identityFileName: append(encoded, '\n'),
	} {
		if err := replaceFileSync(filepath.Join(directory, name), value); err != nil {
			return fmt.Errorf("%w: write identity material", ErrPersistence)
		}
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("%w: sync identity material", ErrPersistence)
	}
	if err := os.Remove(filepath.Join(directory, pendingFileName)); err != nil {
		return fmt.Errorf("%w: finalize recovery state", ErrPersistence)
	}
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("%w: sync finalized identity", ErrPersistence)
	}
	return nil
}

func completedPending(directory string, expectedFingerprint []byte) (bool, Result) {
	if !exists(directory) || exists(filepath.Join(directory, pendingFileName)) || validateSecureDirectory(directory) != nil {
		return false, Result{}
	}
	identity, err := readIdentity(directory)
	if err != nil {
		return false, Result{}
	}
	fingerprint, err := base64.RawStdEncoding.DecodeString(identity.MachineFingerprintSHA256)
	if err != nil || !bytes.Equal(fingerprint, expectedFingerprint) {
		return false, Result{}
	}
	return true, resultFor(directory, identity)
}

func LoadIdentity(directory string, now time.Time) (Identity, error) {
	return loadPublicIdentity(directory, now, false)
}

// LoadIdentityAllowingExpired is LoadIdentity that also accepts a client
// certificate past its NotAfter (ADR 0013 GW-02): the key pair, SAN and chain
// are still verified (at the certificate's last valid instant), and
// Identity.CertificateExpired tells the agent to recover before connecting.
// A certificate that is not yet valid is still refused.
func LoadIdentityAllowingExpired(directory string, now time.Time) (Identity, error) {
	return loadPublicIdentity(directory, now, true)
}

func loadPublicIdentity(directory string, now time.Time, allowExpired bool) (Identity, error) {
	if now.IsZero() || validateSecureDirectory(directory) != nil {
		return Identity{}, ErrInvalidIdentity
	}
	state, identity, expired, err := loadIdentityAt(directory, now, allowExpired)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		NodeID: state.NodeID, CertificateExpired: expired,
		ProtocolMajor: state.SelectedProtocolMajor, ProtocolMinor: state.SelectedProtocolMinor,
		ArtifactEncryptionKeyID:      state.ArtifactEncryptionKeyID,
		ClientCertificateFile:        filepath.Join(directory, clientCertFileName),
		ClientPrivateKeyFile:         filepath.Join(directory, clientKeyFileName),
		ArtifactPrivateKeyFile:       filepath.Join(directory, artifactKeyFileName),
		ArtifactEncryptionPrivateKey: identity,
	}, nil
}

func commitPending(pendingDir, identityDir string) error {
	if exists(identityDir) {
		return ErrAlreadyEnrolled
	}
	if err := renameNoReplace(pendingDir, identityDir); err != nil {
		if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTEMPTY) {
			return ErrAlreadyEnrolled
		}
		return fmt.Errorf("%w: commit identity directory", ErrPersistence)
	}
	if err := syncDirectory(filepath.Dir(identityDir)); err != nil {
		return fmt.Errorf("%w: sync identity parent", ErrPersistence)
	}
	return nil
}

func readIdentity(directory string) (identityState, error) {
	state, privateKey, err := loadIdentity(directory, time.Now())
	clear(privateKey)
	return state, err
}

func loadIdentity(directory string, now time.Time) (identityState, []byte, error) {
	state, artifactKey, _, err := loadIdentityAt(directory, now, false)
	return state, artifactKey, err
}

// loadIdentityAt verifies the identity at now; with allowExpired a leaf past
// NotAfter is verified at its last valid second instead and reported expired.
func loadIdentityAt(directory string, now time.Time, allowExpired bool) (identityState, []byte, bool, error) {
	content, err := readRegular(filepath.Join(directory, identityFileName), maxSecurityFile, true)
	if err != nil {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	var identity identityState
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&identity) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	fingerprint, fingerprintErr := base64.RawStdEncoding.DecodeString(identity.MachineFingerprintSHA256)
	if identity.Version != 1 || !canonicalUUID(identity.NodeID) || identity.SelectedProtocolMajor == 0 || fingerprintErr != nil || len(fingerprint) != sha256.Size || identity.ClientCertificateFile != clientCertFileName || identity.ClientPrivateKeyFile != clientKeyFileName || identity.ArtifactEncryptionPrivateKeyFile != artifactKeyFileName || !validArtifactKeyID(identity.ArtifactEncryptionKeyID) {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	certificatePEM, err := readRegular(filepath.Join(directory, clientCertFileName), maxSecurityFile, true)
	if err != nil {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	privatePEM, err := readRegular(filepath.Join(directory, clientKeyFileName), maxSecurityFile, true)
	if err != nil {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	pair, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil || len(pair.Certificate) < 2 {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	certificates := make([]*x509.Certificate, len(pair.Certificate))
	for index := range pair.Certificate {
		certificates[index], err = x509.ParseCertificate(pair.Certificate[index])
		if err != nil {
			return identityState{}, nil, false, ErrInvalidIdentity
		}
	}
	leaf := certificates[0]
	leafPublic, leafIsEd25519 := leaf.PublicKey.(ed25519.PublicKey)
	signer, signerOK := pair.PrivateKey.(interface{ Public() crypto.PublicKey })
	if !signerOK {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	privatePublic, privateIsEd25519 := signer.Public().(ed25519.PublicKey)
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != nodeSPIFFEPrefix+identity.NodeID ||
		len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 ||
		!leafIsEd25519 || !privateIsEd25519 || !bytes.Equal(leafPublic, privatePublic) ||
		now.Before(leaf.NotBefore) {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	for index := 1; index < len(certificates); index++ {
		certificate := certificates[index]
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			certificates[index-1].CheckSignatureFrom(certificate) != nil {
			return identityState{}, nil, false, ErrInvalidIdentity
		}
	}
	expired := !now.Before(leaf.NotAfter)
	if expired && !allowExpired {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	verifyAt := now
	if expired {
		verifyAt = leaf.NotAfter.Add(-time.Second)
	}
	root := certificates[len(certificates)-1]
	if root.CheckSignatureFrom(root) != nil {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, certificate := range certificates[1 : len(certificates)-1] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: verifyAt, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	artifactBytes, err := readRegular(filepath.Join(directory, artifactKeyFileName), 32, true)
	if err != nil || len(artifactBytes) != 32 {
		clear(artifactBytes)
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	artifactKey, err := ecdh.X25519().NewPrivateKey(artifactBytes)
	if err != nil {
		clear(artifactBytes)
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	digest := sha256.Sum256(artifactKey.PublicKey().Bytes())
	if identity.ArtifactEncryptionKeyID != "x25519:"+hex.EncodeToString(digest[:]) {
		clear(artifactBytes)
		return identityState{}, nil, false, ErrInvalidIdentity
	}
	return identity, artifactBytes, expired, nil
}

func resultFor(directory string, identity identityState) Result {
	return Result{
		NodeID: identity.NodeID, ProtocolMajor: identity.SelectedProtocolMajor, ProtocolMinor: identity.SelectedProtocolMinor,
		ArtifactEncryptionKeyID: identity.ArtifactEncryptionKeyID,
		IdentityFile:            filepath.Join(directory, identityFileName), ClientCertificateFile: filepath.Join(directory, clientCertFileName),
		ClientPrivateKeyFile: filepath.Join(directory, clientKeyFileName), ArtifactPrivateKeyFile: filepath.Join(directory, artifactKeyFileName),
	}
}

type enrollmentLock struct{ file *os.File }

func acquireLock(identityDir string) (*enrollmentLock, error) {
	path := identityDir + lockSuffix
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open enrollment lock", ErrPersistence)
	}
	file := os.NewFile(uintptr(fd), path)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, fmt.Errorf("%w: enrollment lock is unsafe", ErrPersistence)
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("%w: secure enrollment lock", ErrPersistence)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrEnrollmentBusy
		}
		return nil, fmt.Errorf("%w: lock enrollment", ErrPersistence)
	}
	return &enrollmentLock{file: file}, nil
}

func (lock *enrollmentLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	return lock.file.Close()
}

func readRegular(path string, limit int64, ownerOnly bool) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidInput
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || ownerOnly && info.Mode().Perm()&0o077 != 0 || info.Size() < 0 || info.Size() > limit {
		return nil, ErrInvalidInput
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) > limit {
		return nil, ErrInvalidInput
	}
	return value, nil
}

func rejectSymlinkComponents(path string) error {
	current := filepath.VolumeName(path) + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidInput
		}
	}
	return nil
}

func validateSecureDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrInvalidInput
	}
	current := filepath.VolumeName(path) + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidInput
		}
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrInvalidInput
	}
	return nil
}

func replaceFileSync(path string, value []byte) error {
	if err := os.Remove(path + ".tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		temp.Close()
		if !complete {
			_ = os.Remove(temp.Name())
		}
	}()
	if temp.Chmod(0o600) != nil {
		return ErrPersistence
	}
	if _, err := temp.Write(value); err != nil || temp.Sync() != nil || temp.Close() != nil || os.Rename(temp.Name(), path) != nil {
		return ErrPersistence
	}
	complete = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func parseCertificate(value []byte) (*x509.Certificate, error) {
	if len(value) == 0 || len(value) > 65536 {
		return nil, ErrInvalidResponse
	}
	block, remainder := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, ErrInvalidResponse
	}
	return x509.ParseCertificate(block.Bytes)
}

func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() == nil {
			return true
		}
		if field.IsList() {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknown(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
			return !unknown
		}
		unknown = hasUnknown(value.Message())
		return !unknown
	})
	return unknown
}

func validateVersionRange(value *commonv1.ProtocolVersionRange) error {
	if value == nil || value.Minimum == nil || value.Maximum == nil || value.Minimum.Major == 0 || value.Maximum.Major == 0 || compareVersion(value.Minimum, value.Maximum) > 0 {
		return ErrInvalidInput
	}
	return nil
}

func versionInRange(value *commonv1.ProtocolVersion, supported *commonv1.ProtocolVersionRange) bool {
	return value != nil && value.Major != 0 && validateVersionRange(supported) == nil && compareVersion(value, supported.Minimum) >= 0 && compareVersion(value, supported.Maximum) <= 0
}

func compareVersion(left, right *commonv1.ProtocolVersion) int {
	if left.Major < right.Major || left.Major == right.Major && left.Minor < right.Minor {
		return -1
	}
	if left.Major == right.Major && left.Minor == right.Minor {
		return 0
	}
	return 1
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validArtifactKeyID(value string) bool {
	if !strings.HasPrefix(value, "x25519:") || len(value) != len("x25519:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "x25519:"))
	return err == nil && len(decoded) == sha256.Size
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func csrPublicKey(csr *x509.CertificateRequest) (ed25519.PublicKey, bool) {
	if csr == nil {
		return nil, false
	}
	key, ok := csr.PublicKey.(ed25519.PublicKey)
	return key, ok && len(key) == ed25519.PublicKeySize
}
