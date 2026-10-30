package node

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Self-registration follows the competitor model: every node runs the same
// install command carrying one scope-level registration credential, and the
// node record is created only when the host calls Register.
//
// The credential is nrk1.<key-id>.<HMAC(secret, scope, key-id)>. The secret
// never reaches the database; the current key ID and the credential SHA-256
// are recorded as an append-only audit event, so a reset (new key ID)
// invalidates every previously copied command without a schema change.
const (
	registrationCredentialPrefix = "nrk1."
	// RegistrationTokenTTL bounds the one-time enrollment token handed to a
	// registering host; the installer consumes it immediately.
	RegistrationTokenTTL = 10 * time.Minute
	// MaxPendingRegistrations caps pending nodes so a leaked credential
	// cannot grow the inventory without bound.
	MaxPendingRegistrations = 200
	// registeredNodeGenerations allows the same machine to register again
	// after its previous node was deleted (retired).
	registeredNodeGenerations = 64

	auditActionRegistrationCredential = "node.registration_credential.issue"
	auditResourceRegistrationKey      = "node_registration_credential"
	auditActionNodeRegister           = "node.register"
)

var (
	ErrRegistrationUnavailable       = errors.New("node self-registration is not configured")
	ErrInvalidRegistrationCredential = errors.New("invalid node registration credential")
	ErrNodeAlreadyRegistered         = errors.New("node is already registered")
	ErrRegistrationLimit             = errors.New("too many pending node registrations")

	registrationCredentialPattern = regexp.MustCompile(`^nrk1\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$`)
	machineFingerprintPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// RegistrationCredential is shown only to platform node managers.
type RegistrationCredential struct {
	KeyID      uuid.UUID `json:"key_id"`
	Credential string    `json:"credential"`
	IssuedAt   time.Time `json:"issued_at"`
}

type RegisterRequest struct {
	Credential string
	// MachineFingerprint is lowercase hex SHA-256 computed by install-node.sh:
	// sha256("cdnca-node-registration-v1\0" + machine-id + "\0" + DMI product_uuid).
	MachineFingerprint string
	Hostname           string
	OSName             string
	KernelVersion      string
	Architecture       string
	SourceIP           string
	// PublicIP is the address install-node.sh detected (NIC, external
	// probes) or the operator typed. It is used when the request's source is
	// not a public address (control plane reached over a private network).
	PublicIP  string
	RequestID string
}

type RegisterResult struct {
	Node            Node        `json:"node"`
	EnrollmentToken IssuedToken `json:"enrollment_token"`
	Reused          bool        `json:"reused"`
}

type registrationKeys struct {
	credentialKey []byte
	nodeIDKey     []byte
}

func newRegistrationKeys(secret []byte) (registrationKeys, error) {
	if len(secret) < 32 {
		return registrationKeys{}, ErrRegistrationUnavailable
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	return registrationKeys{
		credentialKey: derive("cdnca-node-registration-credential-v1"),
		nodeIDKey:     derive("cdnca-node-registration-node-id-v1"),
	}, nil
}

func (k registrationKeys) configured() bool {
	return len(k.credentialKey) == 32 && len(k.nodeIDKey) == 32
}

func (k registrationKeys) credential(scopeID, keyID uuid.UUID) string {
	mac := hmac.New(sha256.New, k.credentialKey)
	_, _ = mac.Write(scopeID[:])
	_, _ = mac.Write(keyID[:])
	return registrationCredentialPrefix + hex.EncodeToString(keyID[:]) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyCredential checks the MAC without touching the database, so forged
// credentials are rejected before any lock or query.
func (k registrationKeys) verifyCredential(scopeID uuid.UUID, credential string) (uuid.UUID, error) {
	if !k.configured() || !registrationCredentialPattern.MatchString(credential) {
		return uuid.Nil, ErrInvalidRegistrationCredential
	}
	raw, err := hex.DecodeString(credential[len(registrationCredentialPrefix) : len(registrationCredentialPrefix)+32])
	if err != nil {
		return uuid.Nil, ErrInvalidRegistrationCredential
	}
	keyID, err := uuid.FromBytes(raw)
	if err != nil || keyID == uuid.Nil ||
		!hmac.Equal([]byte(k.credential(scopeID, keyID)), []byte(credential)) {
		return uuid.Nil, ErrInvalidRegistrationCredential
	}
	return keyID, nil
}

// registeredNodeID derives a stable UUIDv8 per (scope, machine, generation).
// The keyed hash keeps the machine fingerprint unlinkable from node IDs, and
// version 8 marks the node as self-registered (console reservations use v7).
func (k registrationKeys) registeredNodeID(scopeID uuid.UUID, fingerprint []byte, generation int) uuid.UUID {
	mac := hmac.New(sha256.New, k.nodeIDKey)
	_, _ = mac.Write(scopeID[:])
	_, _ = mac.Write(fingerprint)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], uint32(generation))
	_, _ = mac.Write(counter[:])
	var id uuid.UUID
	copy(id[:], mac.Sum(nil))
	id[6] = (id[6] & 0x0f) | 0x80
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

// IsSelfRegisteredNodeID reports whether the node was created by Register.
// Such nodes stay pending after enrollment until an administrator initializes
// them; console-reserved (UUIDv7) nodes keep the legacy auto-activation.
func IsSelfRegisteredNodeID(id uuid.UUID) bool {
	return id.Version() == 8 && id.Variant() == uuid.RFC4122
}

func credentialDigest(credential string) []byte {
	digest := sha256.Sum256([]byte(credential))
	return digest[:]
}

type normalizedRegistration struct {
	fingerprint []byte
	hostname    string
	description string
	ipv4        string
	ipv6        string
}

func normalizeRegisterRequest(request RegisterRequest) (normalizedRegistration, error) {
	if request.Credential == "" || !validWriteMetadata(request.RequestID, request.RequestID) ||
		!machineFingerprintPattern.MatchString(request.MachineFingerprint) {
		return normalizedRegistration{}, ErrInvalidInput
	}
	fingerprint, _ := hex.DecodeString(request.MachineFingerprint)
	hostname := strings.TrimSpace(request.Hostname)
	parts := make([]string, 0, 3)
	for _, value := range []*string{&hostname, &request.OSName, &request.KernelVersion, &request.Architecture} {
		*value = strings.TrimSpace(*value)
		if !validRegistrationText(*value) {
			return normalizedRegistration{}, ErrInvalidInput
		}
	}
	for _, value := range []string{request.OSName, request.KernelVersion, request.Architecture} {
		if value != "" {
			parts = append(parts, value)
		}
	}
	if hostname == "" {
		hostname = "node"
	}
	result := normalizedRegistration{
		fingerprint: fingerprint, hostname: hostname, description: strings.Join(parts, " · "),
	}
	// The node's public IP, in order: the observed public source address of
	// this request, then the address the installer reported. NAT, loopback
	// and link-local sources are left empty for the administrator or network
	// inventory; a private source is used only when nothing better came.
	source := net.ParseIP(strings.TrimSpace(request.SourceIP))
	reported := net.ParseIP(strings.TrimSpace(request.PublicIP))
	var chosen net.IP
	switch {
	case publicAddress(source):
		chosen = source
	case publicAddress(reported):
		chosen = reported
	case source != nil && source.IsGlobalUnicast():
		chosen = source
	}
	if chosen != nil {
		if chosen.To4() != nil {
			result.ipv4 = chosen.To4().String()
		} else {
			result.ipv6 = chosen.String()
		}
	}
	return result, nil
}

// publicAddress: global unicast and not private (RFC 1918 / ULA), shared
// (100.64/10) or documentation space.
func publicAddress(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, block := range nonPublicBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublicBlocks = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{"100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, block, _ := net.ParseCIDR(cidr)
		out = append(out, block)
	}
	return out
}()

func validRegistrationText(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ConfigureRegistration enables self-registration with a server-side secret
// (the API key pepper). Without it the registration endpoints fail closed.
func (s *Service) ConfigureRegistration(secret []byte) error {
	keys, err := newRegistrationKeys(secret)
	if err != nil {
		return err
	}
	s.registration = keys
	return nil
}

// RegistrationCredential returns the current credential, issuing the first one
// (or a replacement after the server secret changed) under the scope lock.
func (s *Service) RegistrationCredential(ctx context.Context, actor Actor, requestID string) (RegistrationCredential, error) {
	return s.registrationCredential(ctx, actor, requestID, false)
}

// ResetRegistrationCredential issues a new key ID; commands carrying the old
// credential are rejected from then on. Installed nodes are unaffected.
func (s *Service) ResetRegistrationCredential(ctx context.Context, actor Actor, requestID string) (RegistrationCredential, error) {
	return s.registrationCredential(ctx, actor, requestID, true)
}

func (s *Service) registrationCredential(ctx context.Context, actor Actor, requestID string, reset bool) (RegistrationCredential, error) {
	if !s.registration.configured() {
		return RegistrationCredential{}, ErrRegistrationUnavailable
	}
	if !validActor(actor) || !validWriteMetadata(requestID, requestID) {
		return RegistrationCredential{}, ErrInvalidInput
	}
	return s.store.registrationCredential(ctx, s.registration, actor, requestID, reset)
}

// Register creates (or reuses) a pending node for the calling machine and
// returns a one-time enrollment token for it.
func (s *Service) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	if !s.registration.configured() {
		return RegisterResult{}, ErrRegistrationUnavailable
	}
	normalized, err := normalizeRegisterRequest(request)
	if err != nil {
		return RegisterResult{}, err
	}
	return s.store.register(ctx, s.registration, request, normalized)
}
