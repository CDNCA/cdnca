package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Install resume (fz-x13): the Gateway enrollment committed on the controller
// but its response never reached this host, so <identity>.enrolling still
// holds pending.json (private keys, CSR). The installer reads the CSR digest,
// fetches the issued certificate from the controller with the registration
// credential, and Resume assembles the identity exactly as Run would have.

const maxRecoveryResponse = 1 << 20

type ResumeConfig struct {
	IdentityDir       string
	MachineIDFile     string
	SupportedVersions *commonv1.ProtocolVersionRange
	Now               func() time.Time
}

// PendingCSRSHA256 returns the lowercase hex SHA-256 of the pending CSR DER,
// the value the controller stored as node_identity_authorizations.csr_sha256.
func PendingCSRSHA256(identityDir string) (string, error) {
	if !cleanAbsolute(identityDir) {
		return "", fmt.Errorf("%w: identity directory must be absolute and clean", ErrInvalidInput)
	}
	prepared, err := readPending(identityDir + pendingSuffix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(prepared.csrDER)
	return hex.EncodeToString(digest[:]), nil
}

// Resume commits the identity from the pending state and the controller's
// copy of the enrollment response (agent.v1.EnrollResponse as protojson). It
// never creates new pending state: without pending.json there is nothing the
// response could belong to.
func Resume(config ResumeConfig, response []byte) (Result, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if !cleanAbsolute(config.IdentityDir) || !cleanAbsolute(config.MachineIDFile) || validateVersionRange(config.SupportedVersions) != nil {
		return Result{}, fmt.Errorf("%w: recovery paths and protocol versions are required", ErrInvalidInput)
	}
	if err := validateSecureDirectory(filepath.Dir(config.IdentityDir)); err != nil {
		return Result{}, err
	}
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
	// The files were written but the directory rename was interrupted; the
	// response is not needed (the installer passes an empty file).
	if complete, result := completedPending(pendingDir, fingerprint); complete {
		if err := commitPending(pendingDir, config.IdentityDir); err != nil {
			return Result{}, err
		}
		return result, nil
	}
	if len(response) == 0 || len(response) > maxRecoveryResponse {
		return Result{}, ErrInvalidResponse
	}
	prepared, err := readPending(pendingDir)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(prepared.fingerprint, fingerprint) {
		return Result{}, fmt.Errorf("%w: machine identity changed", ErrRecoveryState)
	}
	var message agentv1.EnrollResponse
	if err := protojson.Unmarshal(response, &message); err != nil {
		return Result{}, ErrInvalidResponse
	}
	identity, certificatePEM, err := validateResponse(&message, config.SupportedVersions,
		prepared.privateKey.Public().(ed25519.PublicKey), prepared.artifactKey, config.Now())
	if err != nil {
		return Result{}, err
	}
	identity.MachineFingerprintSHA256 = base64.RawStdEncoding.EncodeToString(prepared.fingerprint)
	privateDER, err := x509.MarshalPKCS8PrivateKey(prepared.privateKey)
	if err != nil {
		return Result{}, fmt.Errorf("%w: encode client private key", ErrPersistence)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privateDER)
	defer clear(privatePEM)
	if err := writeFinalFiles(pendingDir, identity, certificatePEM, privatePEM, prepared.artifactKey.Bytes()); err != nil {
		return Result{}, err
	}
	if err := commitPending(pendingDir, config.IdentityDir); err != nil {
		return Result{}, err
	}
	return resultFor(config.IdentityDir, identity), nil
}

// ReadRecoveryResponseFile reads the controller response the installer
// saved (owner-only regular file, no symlinks).
func ReadRecoveryResponseFile(path string) ([]byte, error) {
	value, err := readRegular(path, maxRecoveryResponse, true)
	if err != nil {
		return nil, fmt.Errorf("%w: recovery response file is unsafe", ErrInvalidInput)
	}
	return value, nil
}

func readPending(pendingDir string) (preparedEnrollment, error) {
	if !exists(pendingDir) || validateSecureDirectory(pendingDir) != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: no pending enrollment", ErrRecoveryState)
	}
	content, err := readRegular(filepath.Join(pendingDir, pendingFileName), maxSecurityFile, true)
	if err != nil {
		return preparedEnrollment{}, fmt.Errorf("%w: pending state is incomplete", ErrRecoveryState)
	}
	return decodePending(content)
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}
