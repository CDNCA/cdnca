package dnsproviderremote

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/google/uuid"
)

type ErrorCode string

const (
	CodeInvalidInput        ErrorCode = "dns_provider_remote_invalid_input"
	CodeSourceUnavailable   ErrorCode = "dns_provider_remote_source_unavailable"
	CodeUnsupported         ErrorCode = "dns_provider_remote_unsupported"
	CodeCredentialsRejected ErrorCode = "dns_provider_remote_credentials_rejected"
	CodeRateLimited         ErrorCode = "dns_provider_remote_rate_limited"
	CodeUnavailable         ErrorCode = "dns_provider_remote_unavailable"
	CodeInvalidResponse     ErrorCode = "dns_provider_remote_invalid_response"
	CodeRecordNotFound      ErrorCode = "dns_provider_remote_record_not_found"
	CodeRecordMismatch      ErrorCode = "dns_provider_remote_record_mismatch"
	CodeTimeout             ErrorCode = "dns_provider_remote_timeout"
	CodeCancelled           ErrorCode = "dns_provider_remote_cancelled"
	// CodeLineNotInPlan: the provider account's plan has no such line (the
	// configured plan tier excludes it, or the provider refused or does not
	// list it). The line falls back to the default line's answer.
	CodeLineNotInPlan ErrorCode = "dns_provider_remote_line_not_in_plan"
	// CodeZoneNotHosted: the provider account does not host the zone by this
	// name (DNSPod code 13), e.g. a CNAME zone that is a subdomain of the
	// hosted domain.
	CodeZoneNotHosted ErrorCode = "dns_zone_not_hosted"
)

// ProviderCapability describes only behavior implemented by this package. It
// does not imply that a provider sandbox or production account was exercised.
type ProviderCapability struct {
	ProviderType             string
	DNS01TXT                 bool
	ReconcileA               bool
	ReconcileAAAA            bool
	ReconcileCNAME           bool
	Line                     bool
	Weight                   bool
	RetryAfterClassification bool
}

// ProviderCapabilityMatrix returns a fresh fixed-size value so callers cannot
// mutate the package's code-authoritative provider capability contract.
func ProviderCapabilityMatrix() [9]ProviderCapability {
	return [9]ProviderCapability{
		{ProviderType: providerAliyun, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerCloudflare, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, RetryAfterClassification: true},
		{ProviderType: providerHuawei, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerDNSPodCN, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, Weight: true, RetryAfterClassification: true},
		// Lines open per the credential's plan tier (dnsComPlanLines).
		{ProviderType: providerDNSCom, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		{ProviderType: providerDNSLA, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true, RetryAfterClassification: true},
		// name.com records have no line field: default line only; TTL floor 300.
		{ProviderType: providerNameCom, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, RetryAfterClassification: true},
		// The endpoint receives unified line names and maps them itself.
		{ProviderType: providerCustomHTTP, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true},
		// Third-party DNS plugins speak the same unified lines (PA-22 contract).
		{ProviderType: providerPlugin, DNS01TXT: true, ReconcileA: true, ReconcileAAAA: true, ReconcileCNAME: true, Line: true},
	}
}

func providerCapabilityFor(providerType string) (ProviderCapability, bool) {
	for _, capability := range ProviderCapabilityMatrix() {
		if capability.ProviderType == providerType {
			return capability, true
		}
	}
	return ProviderCapability{}, false
}

// Error deliberately exposes only stable classification. Provider response
// bodies, transport details, and credentials are never retained.
type Error struct {
	Code       ErrorCode
	RetryAfter time.Duration
	Temporary  bool
}

func (e *Error) Error() string { return string(e.Code) }

func (e *Error) Is(target error) bool {
	switch target {
	case context.Canceled:
		return e.Code == CodeCancelled
	case context.DeadlineExceeded:
		return e.Code == CodeTimeout
	default:
		other, ok := target.(*Error)
		return ok && other.Code == e.Code
	}
}

func ErrorCodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

type ProviderConfig struct {
	TenantID    uuid.UUID
	ScopeID     uuid.UUID
	OperationID string
	ActorUserID uuid.UUID
	// TenantScopeID is retained only for non-production legacy sources.
	TenantScopeID uuid.UUID
	ProviderID    uuid.UUID
	ProviderType  string
	ZoneID        uuid.UUID
	ZoneName      string
	// ProviderZoneName is the domain the DNS account hosts (migration 473
	// dns_zones.provider_zone_apex): ZoneName itself or a parent of it, e.g.
	// 868yun.com for the CNAME zone cdn.868yun.com. Empty means ZoneName.
	// validateConfig checks owners against ZoneName, then replaces ZoneName
	// with this apex, so every provider call and relative record name
	// (5ksukk1m.cdn) is based on the hosted domain.
	ProviderZoneName string
	Credentials      map[string]string
	// CredentialVersion is an opaque durable fence. A zero value preserves
	// compatibility with legacy test sources that have no durable fence.
	CredentialVersion uint64
	CredentialRevoked bool
}

type safeProviderConfig struct {
	ProviderType          string `json:"provider_type"`
	CredentialsConfigured bool   `json:"credentials_configured"`
	CredentialVersion     uint64 `json:"credential_version"`
	CredentialRevoked     bool   `json:"credential_revoked"`
}

func (config ProviderConfig) safe() safeProviderConfig {
	return safeProviderConfig{
		ProviderType: config.ProviderType, CredentialsConfigured: len(config.Credentials) > 0,
		CredentialVersion: config.CredentialVersion, CredentialRevoked: config.CredentialRevoked,
	}
}

func (config ProviderConfig) String() string {
	encoded, _ := json.Marshal(config.safe())
	return string(encoded)
}

func (config ProviderConfig) GoString() string { return config.String() }

func (config ProviderConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, config.String())
}

func (config ProviderConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(config.safe())
}

type ProviderLookup struct {
	TenantID    uuid.UUID
	ScopeID     uuid.UUID
	OperationID string
	ActorUserID uuid.UUID
	// TenantScopeID is retained only for non-production legacy sources.
	TenantScopeID uuid.UUID
	ProviderID    uuid.UUID
	// ZoneID is Nil only for PresentTXT and legacy v1 cleanup. V2 observe/delete
	// always supply the authenticated managed-zone UUID from the handle.
	ZoneID    uuid.UUID
	OwnerName string
}

// Source resolves provider authority and credentials for every challenge. It
// must not retain a constructor-bound tenant or reuse a prior lookup result.
type Source interface {
	Resolve(ctx context.Context, lookup ProviderLookup) (ProviderConfig, error)
}

type credentialFenceSource interface {
	CheckCredentialFence(ctx context.Context, lookup ProviderLookup, version uint64) error
}

type ProviderCredentialLease func(context.Context) error

type ProviderCredentialLeaseAuthority interface {
	AcquireProviderCredentialLease(context.Context, ProviderLookup, uint64) (ProviderCredentialLease, error)
}

type StartupSource interface {
	Source
	OutstandingRemoteTXTHandles(ctx context.Context) ([]acmeworker.ChallengeIdentity, error)
}

// TXTRecovery is the optional recovery boundary used when a provider may have
// accepted PresentTXT but its response was not durably observed. Zero exact
// matches are a successful absence; only one exact match may become a signed
// handle, while more than one returns CodeRecordMismatch.
type TXTRecovery interface {
	RecoverTXT(context.Context, acmeworker.ChallengeIdentity) (acmeworker.RemoteTXTHandle, bool, error)
}

type HandleKey struct {
	ID     string
	Secret []byte
}

type HandleKeyring struct {
	activeID string
	keys     map[string][sha256.Size]byte
}

func NewHandleKeyring(active HandleKey, verifyOnly ...HandleKey) (*HandleKeyring, error) {
	keys := make(map[string][sha256.Size]byte, len(verifyOnly)+1)
	for _, key := range append([]HandleKey{active}, verifyOnly...) {
		if !validHandleKeyID(key.ID) || len(key.Secret) != sha256.Size {
			return nil, failure(CodeInvalidInput, false)
		}
		if _, duplicate := keys[key.ID]; duplicate {
			return nil, failure(CodeInvalidInput, false)
		}
		var copied [sha256.Size]byte
		copy(copied[:], key.Secret)
		keys[key.ID] = copied
	}
	return &HandleKeyring{activeID: active.ID, keys: keys}, nil
}

type recordHandle struct {
	Version  int    `json:"v"`
	Provider string `json:"p"`
	Zone     string `json:"z"`
	ZoneID   string `json:"zi"`
	RecordID string `json:"ri"`
	Owner    string `json:"o"`
}

type remoteRecord struct {
	Owner string
	Type  string
	Value string
}

type remoteProvider interface {
	present(context.Context, ProviderConfig, string, string, string) (recordHandle, error)
	lookupTXT(context.Context, ProviderConfig, string, string, string) ([]recordHandle, error)
	get(context.Context, ProviderConfig, recordHandle, string) (remoteRecord, bool, error)
	delete(context.Context, ProviderConfig, recordHandle) error
}

func clearProviderConfig(config *ProviderConfig) {
	if config == nil {
		return
	}
	for name := range config.Credentials {
		config.Credentials[name] = ""
		delete(config.Credentials, name)
	}
	config.Credentials = nil
	config.OperationID = ""
	config.ActorUserID = uuid.Nil
}

const (
	handlePrefix       = "v2."
	legacyHandlePrefix = "v1."
	handleMACDomain    = "cdnca-dns-remote-handle/v2\x00"
	maxHandleLength    = 2048
)

type handlePayload struct {
	TenantID         string `json:"t"`
	ScopeID          string `json:"s"`
	TenantScopeID    string `json:"-"`
	OperationID      string `json:"o"`
	AttemptID        string `json:"a"`
	ProviderID       string `json:"p"`
	ProviderType     string `json:"pt"`
	ManagedZoneID    string `json:"z"`
	ZoneNameSHA256   string `json:"zn"`
	OwnerSHA256      string `json:"on"`
	ExactValueSHA256 string `json:"x"`
	RemoteZoneID     string `json:"rz"`
	RemoteRecordID   string `json:"rr"`
}

func encodeHandle(
	challenge acmeworker.ChallengeIdentity,
	config ProviderConfig,
	handle recordHandle,
	keyring *HandleKeyring,
) (acmeworker.RemoteTXTHandle, error) {
	owner, err := validateChallenge(challenge)
	if err != nil || keyring == nil {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidInput, false)
	}
	config, _, err = validateConfig(config, owner)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	providerID, _ := uuid.Parse(challenge.ProviderRef)
	if config.TenantID != challenge.TenantID || config.ScopeID != challenge.ScopeID ||
		config.ProviderID != challenge.ProviderID || config.ProviderID != providerID ||
		config.ZoneID != challenge.ZoneID ||
		handle.Provider != config.ProviderType || handle.Zone != config.ZoneName || handle.Owner != owner {
		return acmeworker.RemoteTXTHandle{}, failure(CodeRecordMismatch, false)
	}
	handle.Version = 1
	if err := validateRecordHandle(handle); err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	payload := handlePayload{
		TenantID: challenge.TenantID.String(), ScopeID: challenge.ScopeID.String(), OperationID: challenge.OperationID,
		AttemptID: challenge.AttemptID.String(), ProviderID: challenge.ProviderRef,
		ProviderType: config.ProviderType, ManagedZoneID: config.ZoneID.String(),
		ZoneNameSHA256: digestText(config.ZoneName), OwnerSHA256: digestText(owner),
		ExactValueSHA256: digestText(challenge.ExactValue),
		RemoteZoneID:     handle.ZoneID, RemoteRecordID: handle.RecordID,
	}
	if err := validateHandlePayload(payload); err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	canonical, err := canonicalHandlePayload(payload)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidResponse, false)
	}
	key, ok := keyring.keys[keyring.activeID]
	if !ok {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidInput, false)
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(handleMACInput(keyring.activeID, canonical))
	recordRef := handlePrefix + keyring.activeID + "." + base64.RawURLEncoding.EncodeToString(canonical) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(recordRef) >= maxHandleLength {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidResponse, false)
	}
	return acmeworker.RemoteTXTHandle{ProviderRef: challenge.ProviderRef, RecordRef: recordRef}, nil
}

func decodeHandle(recordRef string, keyring *HandleKeyring) (handlePayload, error) {
	if keyring == nil || !validReference(recordRef, maxHandleLength) || !strings.HasPrefix(recordRef, handlePrefix) {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	parts := strings.Split(recordRef, ".")
	if len(parts) != 4 || parts[0] != "v2" || !validHandleKeyID(parts[1]) || parts[2] == "" || parts[3] == "" {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	canonical, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(canonical) == 0 || len(canonical) > 1536 {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(providedMAC) != sha256.Size {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	key, ok := keyring.keys[parts[1]]
	if !ok {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(handleMACInput(parts[1], canonical))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}

	var payload handlePayload
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	reencoded, err := canonicalHandlePayload(payload)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return handlePayload{}, failure(CodeInvalidInput, false)
	}
	if err := validateHandlePayload(payload); err != nil {
		return handlePayload{}, err
	}
	return payload, nil
}

func encodeLegacyHandle(providerRef string, handle recordHandle) (acmeworker.RemoteTXTHandle, error) {
	handle.Version = 1
	if err := validateRecordHandle(handle); err != nil {
		return acmeworker.RemoteTXTHandle{}, err
	}
	raw, err := json.Marshal(handle)
	if err != nil {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidResponse, false)
	}
	recordRef := legacyHandlePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(recordRef) > 1024 {
		return acmeworker.RemoteTXTHandle{}, failure(CodeInvalidResponse, false)
	}
	return acmeworker.RemoteTXTHandle{ProviderRef: providerRef, RecordRef: recordRef}, nil
}

func decodeLegacyHandle(handle acmeworker.RemoteTXTHandle) (recordHandle, error) {
	if !validReference(handle.ProviderRef, 200) || !strings.HasPrefix(handle.RecordRef, legacyHandlePrefix) ||
		len(handle.RecordRef) > 1024 {
		return recordHandle{}, failure(CodeInvalidInput, false)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(handle.RecordRef, legacyHandlePrefix))
	if err != nil || len(raw) == 0 || len(raw) > 768 {
		return recordHandle{}, failure(CodeInvalidInput, false)
	}
	var decoded recordHandle
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return recordHandle{}, failure(CodeInvalidInput, false)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return recordHandle{}, failure(CodeInvalidInput, false)
	}
	if err := validateRecordHandle(decoded); err != nil {
		return recordHandle{}, err
	}
	return decoded, nil
}

func canonicalHandlePayload(payload handlePayload) ([]byte, error) { return json.Marshal(payload) }

func handleMACInput(keyID string, payload []byte) []byte {
	result := make([]byte, 0, len(handleMACDomain)+len(keyID)+1+len(payload))
	result = append(result, handleMACDomain...)
	result = append(result, keyID...)
	result = append(result, 0)
	return append(result, payload...)
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func validHandleKeyID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func validateHandlePayload(payload handlePayload) error {
	for _, value := range []string{
		payload.TenantID, payload.ScopeID, payload.AttemptID, payload.ProviderID, payload.ManagedZoneID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return failure(CodeInvalidInput, false)
		}
	}
	if payload.ProviderType == "dnsdun" {
		return failure(CodeUnsupported, false)
	}
	if !validReference(payload.OperationID, 200) || !supportedProvider(payload.ProviderType) ||
		!validDigest(payload.ZoneNameSHA256) || !validDigest(payload.OwnerSHA256) ||
		!validDigest(payload.ExactValueSHA256) || !validReference(payload.RemoteZoneID, 256) ||
		!validReference(payload.RemoteRecordID, 256) {
		return failure(CodeInvalidInput, false)
	}
	return nil
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func bindHandlePayload(payload handlePayload, challenge acmeworker.ChallengeIdentity) error {
	owner, err := validateChallenge(challenge)
	if err != nil {
		return err
	}
	if payload.TenantID != challenge.TenantID.String() || payload.ScopeID != challenge.ScopeID.String() ||
		payload.OperationID != challenge.OperationID ||
		payload.AttemptID != challenge.AttemptID.String() || payload.ProviderID != challenge.ProviderRef ||
		payload.ProviderID != challenge.ProviderID.String() || payload.ManagedZoneID != challenge.ZoneID.String() ||
		!digestMatches(payload.OwnerSHA256, owner) || !digestMatches(payload.ExactValueSHA256, challenge.ExactValue) {
		return failure(CodeRecordMismatch, false)
	}
	return nil
}

func digestMatches(encoded, value string) bool {
	want, err := base64.RawURLEncoding.DecodeString(encoded)
	got := sha256.Sum256([]byte(value))
	return err == nil && hmac.Equal(want, got[:])
}

func validateRecordHandle(handle recordHandle) error {
	if !supportedProvider(handle.Provider) {
		return failure(CodeUnsupported, false)
	}
	if handle.Version != 1 ||
		!validDNSName(handle.Zone, false) || !validDNSName(handle.Owner, true) ||
		!validReference(handle.ZoneID, 256) || !validReference(handle.RecordID, 256) {
		return failure(CodeInvalidInput, false)
	}
	owner, relative, err := ownerAndRelative(handle.Owner, handle.Zone)
	if err != nil || owner != handle.Owner || relative == "" {
		return failure(CodeInvalidInput, false)
	}
	return nil
}

func validateChallenge(challenge acmeworker.ChallengeIdentity) (string, error) {
	if challenge.ChallengeType != acmeworker.ChallengeDNS01 ||
		challenge.TenantID == uuid.Nil || challenge.ScopeID == uuid.Nil || challenge.AttemptID == uuid.Nil ||
		challenge.ProviderID == uuid.Nil || challenge.ZoneID == uuid.Nil ||
		!validReference(challenge.OperationID, 200) || !validReference(challenge.ProviderRef, 200) ||
		!validExactValue(challenge.ExactValue) {
		return "", failure(CodeInvalidInput, false)
	}
	providerID, err := uuid.Parse(challenge.ProviderRef)
	if err != nil || providerID == uuid.Nil || providerID != challenge.ProviderID ||
		providerID.String() != challenge.ProviderRef {
		return "", failure(CodeInvalidInput, false)
	}
	owner := canonicalDNSName(challenge.RecordName, true)
	if owner == "" || owner != challenge.RecordName {
		return "", failure(CodeInvalidInput, false)
	}
	return owner, nil
}

func validateConfig(config ProviderConfig, owner string) (ProviderConfig, string, error) {
	config.ProviderType = strings.TrimSpace(config.ProviderType)
	config.ZoneName = canonicalDNSName(config.ZoneName, false)
	if config.TenantID == uuid.Nil || config.ScopeID == uuid.Nil ||
		config.TenantScopeID != config.ScopeID || config.ProviderID == uuid.Nil || config.ZoneID == uuid.Nil ||
		(config.OperationID != "" && !validReference(config.OperationID, 200)) ||
		config.ProviderType == "" || config.ZoneName == "" || config.Credentials == nil {
		return ProviderConfig{}, "", failure(CodeInvalidInput, false)
	}
	if !supportedProvider(config.ProviderType) {
		return ProviderConfig{}, "", failure(CodeUnsupported, false)
	}
	apex := config.ZoneName
	if config.ProviderZoneName != "" {
		apex = canonicalDNSName(config.ProviderZoneName, false)
	}
	if !zoneWithinApex(config.ZoneName, apex) {
		return ProviderConfig{}, "", failure(CodeInvalidInput, false)
	}
	canonicalOwner, _, err := ownerAndRelative(owner, config.ZoneName)
	if err != nil || canonicalOwner != owner {
		return ProviderConfig{}, "", failure(CodeInvalidInput, false)
	}
	config.ZoneName, config.ProviderZoneName = apex, apex
	_, relative, err := ownerAndRelative(owner, apex)
	if err != nil {
		return ProviderConfig{}, "", failure(CodeInvalidInput, false)
	}
	if err := validateCredentials(config.ProviderType, config.Credentials); err != nil {
		return ProviderConfig{}, "", err
	}
	return config, relative, nil
}

// zoneWithinApex reports whether zone is apex or a subdomain of it.
func zoneWithinApex(zone, apex string) bool {
	return zone != "" && apex != "" && (zone == apex || strings.HasSuffix(zone, "."+apex))
}

func ownerAndRelative(owner, zone string) (string, string, error) {
	owner = canonicalDNSName(owner, true)
	zone = canonicalDNSName(zone, false)
	if owner == "" || zone == "" {
		return "", "", failure(CodeInvalidInput, false)
	}
	withoutDot := strings.TrimSuffix(owner, ".")
	if withoutDot == zone {
		return owner, "@", nil
	}
	suffix := "." + zone
	if !strings.HasSuffix(withoutDot, suffix) {
		return "", "", failure(CodeInvalidInput, false)
	}
	relative := strings.TrimSuffix(withoutDot, suffix)
	if relative == "" || len(relative) > 253 {
		return "", "", failure(CodeInvalidInput, false)
	}
	return owner, relative, nil
}

func canonicalDNSName(value string, trailingDot bool) string {
	if value == "" || value != strings.TrimSpace(value) || containsControl(value) {
		return ""
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if !validDNSName(value, false) {
		return ""
	}
	if trailingDot {
		return value + "."
	}
	return value
}

func validDNSName(value string, trailingDot bool) bool {
	if trailingDot {
		if !strings.HasSuffix(value, ".") {
			return false
		}
		value = strings.TrimSuffix(value, ".")
	} else if strings.HasSuffix(value, ".") {
		return false
	}
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func validReference(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == strings.TrimSpace(value) && !containsControl(value)
}

func validExactValue(value string) bool {
	if len(value) < 1 || len(value) > 255 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func matchesRecord(record remoteRecord, handle recordHandle, exactValue string) bool {
	return record.Type == "TXT" && canonicalDNSName(record.Owner, true) == handle.Owner &&
		record.Value == exactValue
}

func failure(code ErrorCode, temporary bool) *Error {
	return &Error{Code: code, Temporary: temporary}
}

func sourceFailure(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return contextFailure(ctx.Err())
	}
	return failure(CodeSourceUnavailable, true)
}

func contextFailure(err error) error {
	if errors.Is(err, context.Canceled) {
		return failure(CodeCancelled, false)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failure(CodeTimeout, true)
	}
	return failure(CodeUnavailable, true)
}

func supportedProvider(provider string) bool {
	switch provider {
	case providerCloudflare, providerAliyun, providerHuawei, providerDNSPodCN, providerDNSCom, providerDNSLA, providerNameCom,
		providerCustomHTTP, providerPlugin:
		return true
	default:
		return false
	}
}

var (
	huaweiAccessKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	huaweiProjectIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	dnspodIDPattern        = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

func validateCredentials(provider string, credentials map[string]string) error {
	var fields map[string]credentialRule
	switch provider {
	case providerCloudflare:
		fields = map[string]credentialRule{"api_token": {maximum: 4096}}
	case providerAliyun:
		fields = map[string]credentialRule{
			"access_key_id": {maximum: 4096}, "access_key_secret": {maximum: 4096},
		}
	case providerHuawei:
		fields = map[string]credentialRule{
			"access_key": {maximum: 128}, "secret_key": {maximum: 256},
			"region": {maximum: 32}, "project_id": {maximum: 32},
		}
	case providerDNSPodCN:
		fields = map[string]credentialRule{"dp_id": {maximum: 20}, "dp_key": {maximum: 256}}
	case providerDNSCom:
		fields = map[string]credentialRule{"api_key": {maximum: 128}, "api_secret": {maximum: 256}}
	case providerDNSLA:
		fields = map[string]credentialRule{"api_id": {maximum: 4096}, "api_secret": {maximum: 4096}}
	case providerNameCom:
		fields = map[string]credentialRule{"username": {maximum: 128}, "api_token": {maximum: 256}}
	case providerCustomHTTP:
		// The address policy is applied by the client at connect time.
		if !dnscustomhttp.ValidShape(credentials) {
			return failure(CodeInvalidInput, false)
		}
		return nil
	case providerPlugin:
		// Usability (enabled + contract passed) is checked at every call.
		if len(credentials) != 1 || !validPluginID(credentials[PluginCredentialField]) {
			return failure(CodeInvalidInput, false)
		}
		return nil
	default:
		return failure(CodeUnsupported, false)
	}
	if provider == providerDNSCom {
		// The plan tier is optional (absent = free).
		if plan, ok := credentials[DNSComPlanField]; ok {
			if !validDNSComPlan(plan) {
				return failure(CodeInvalidInput, false)
			}
			fields[DNSComPlanField] = credentialRule{maximum: 16}
		}
	}
	if len(credentials) != len(fields) {
		return failure(CodeInvalidInput, false)
	}
	for name, rule := range fields {
		value, ok := credentials[name]
		if !ok || (provider != providerDNSLA && !rule.valid(value)) {
			return failure(CodeInvalidInput, false)
		}
	}
	switch provider {
	case providerHuawei:
		if !huaweiAccessKeyPattern.MatchString(credentials["access_key"]) ||
			!huaweiProjectIDPattern.MatchString(credentials["project_id"]) || !validHuaweiRegion(credentials["region"]) {
			return failure(CodeInvalidInput, false)
		}
	case providerDNSPodCN:
		if !dnspodIDPattern.MatchString(credentials["dp_id"]) || strings.Contains(credentials["dp_key"], ",") {
			return failure(CodeInvalidInput, false)
		}
	case providerDNSCom:
		if strings.ContainsAny(credentials["api_key"], "&=") {
			return failure(CodeInvalidInput, false)
		}
	case providerNameCom:
		// Basic authentication: the username cannot hold the separator.
		if strings.Contains(credentials["username"], ":") {
			return failure(CodeInvalidInput, false)
		}
	case providerDNSLA:
		if !validDNSLACredential(credentials["api_id"]) || !validDNSLACredential(credentials["api_secret"]) ||
			strings.Contains(credentials["api_id"], ":") {
			return failure(CodeInvalidInput, false)
		}
	}
	return nil
}

type credentialRule struct{ maximum int }

func (r credentialRule) valid(value string) bool {
	if value == "" || len(value) > r.maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validDNSLACredential(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func providerCredentials(config ProviderConfig, names ...string) []string {
	values := make([]string, len(names))
	for index, name := range names {
		values[index] = config.Credentials[name]
	}
	return values
}

func malformedProviderResponse() error { return failure(CodeInvalidResponse, false) }
