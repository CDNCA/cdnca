package identityverificationissuerhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	identityverificationhttp "github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
)

const (
	IssuePath                 = "/internal/v1/identity-verification/evidence"
	WorkloadAudience          = "identity-verification-issuer.v1"
	IssuePermission           = "identity_verification.evidence.issue"
	requestDigestDomain       = "cdnca.identity-verification.issuer-request.v1\x00"
	defaultMaxBodyBytes int64 = 16 << 10
	defaultMaxTTL             = 15 * time.Minute
)

var (
	ErrInvalidConfig       = errors.New("identity verification issuer configuration is invalid")
	ErrInvalidRequest      = errors.New("identity verification issuer request is invalid")
	ErrUnauthenticated     = errors.New("identity verification issuer authentication required")
	ErrPermissionDenied    = errors.New("identity verification issuer permission denied")
	ErrEvidenceInvalid     = errors.New("identity verification issuer evidence is invalid")
	ErrEvidenceUnavailable = errors.New("identity verification issuer evidence unavailable")
	ErrReplayConflict      = errors.New("identity verification issuer replay conflicts with original request")
)

const (
	CodeInvalidRequest         = "identity_verification_issuer_invalid_request"
	CodeAuthenticationRequired = "identity_verification_issuer_authentication_required"
	CodePermissionDenied       = "identity_verification_issuer_permission_denied"
	CodeEvidenceInvalid        = "identity_verification_evidence_invalid"
	CodeEvidenceUnavailable    = "identity_verification_evidence_unavailable"
	CodeReplayConflict         = "identity_verification_idempotency_conflict"
	CodeMethodNotAllowed       = "method_not_allowed"
)

type Clock func() time.Time

// WorkloadPrincipal is produced by the mTLS authenticator. HTTP fields never
// construct or override it.
type WorkloadPrincipal struct {
	WorkloadID             string
	Audience               string
	Permissions            []string
	CertificateFingerprint [sha256.Size]byte
}

func (principal WorkloadPrincipal) Valid() bool {
	return principal.WorkloadID != "" && principal.WorkloadID == strings.TrimSpace(principal.WorkloadID) &&
		len(principal.WorkloadID) <= 128 && validMetadata(principal.WorkloadID) &&
		principal.Audience == WorkloadAudience && len(principal.Permissions) == 1 && hasPermission(principal.Permissions, IssuePermission) &&
		principal.CertificateFingerprint != ([sha256.Size]byte{})
}

func (principal WorkloadPrincipal) String() string {
	return "identityverificationissuerhttp.WorkloadPrincipal{redacted}"
}

func (principal WorkloadPrincipal) GoString() string { return principal.String() }

type Authenticator interface {
	Authenticate(*http.Request) (WorkloadPrincipal, error)
}

type EvidenceResolveRequest struct {
	WorkloadID        string
	Audience          string
	Kind              string
	EvidenceReference string
	ExpiresAt         time.Time
	IdempotencyKey    string
	RequestID         string
	RequestDigest     [sha256.Size]byte
}

// EvidenceResolver is the trusted KMS/object-store boundary. It must return
// digests and opaque references, never plaintext documents or provider errors.
type EvidenceResolver interface {
	Resolve(context.Context, EvidenceResolveRequest) (ResolvedEvidence, error)
}

type ResolvedEvidence struct {
	Principal              identityverificationhttp.RuntimeEvidencePrincipal
	Kind                   string
	PrivateObjectReference string
	PrivateEnvelopeDigest  [sha256.Size]byte
	EvidenceClaimDigest    [sha256.Size]byte
	Evidence               identityverificationhttp.ResolvedEvidence
	ExpiresAt              time.Time
	RequestDigest          [sha256.Size]byte
}

type Issuer interface {
	IssuePrincipal(context.Context, identityverificationhttp.RuntimeEvidencePrincipal, identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error)
}

var _ Issuer = (*identityverificationhttp.PostgresRuntimeEvidenceSource)(nil)

type Dependencies struct {
	Authenticator Authenticator
	Resolver      EvidenceResolver
	Issuer        Issuer
	Clock         Clock
	MaxBodyBytes  int64
	MaxTTL        time.Duration
}

type Handler struct {
	authenticator Authenticator
	resolver      EvidenceResolver
	issuer        Issuer
	now           Clock
	maxBodyBytes  int64
	maxTTL        time.Duration
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if nilInterface(dependencies.Authenticator) || nilInterface(dependencies.Resolver) || nilInterface(dependencies.Issuer) {
		return nil, ErrInvalidConfig
	}
	if dependencies.Clock == nil {
		dependencies.Clock = time.Now
	}
	if dependencies.MaxBodyBytes == 0 {
		dependencies.MaxBodyBytes = defaultMaxBodyBytes
	}
	if dependencies.MaxTTL == 0 {
		dependencies.MaxTTL = defaultMaxTTL
	}
	if dependencies.MaxBodyBytes < 256 || dependencies.MaxBodyBytes > 1<<20 || dependencies.MaxTTL <= 0 || dependencies.MaxTTL > 24*time.Hour {
		return nil, ErrInvalidConfig
	}
	return &Handler{authenticator: dependencies.Authenticator, resolver: dependencies.Resolver,
		issuer: dependencies.Issuer, now: dependencies.Clock, maxBodyBytes: dependencies.MaxBodyBytes,
		maxTTL: dependencies.MaxTTL}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	if request.URL.Path != IssuePath {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeError(writer, request, http.StatusMethodNotAllowed, CodeMethodNotAllowed)
		return
	}
	if err := validateHeaders(request); err != nil {
		handler.writeMappedError(writer, request, err)
		return
	}
	body, err := decodeRequestBody(request, handler.maxBodyBytes)
	if err != nil {
		handler.writeMappedError(writer, request, err)
		return
	}
	principal, err := handler.authenticator.Authenticate(request)
	if err != nil {
		handler.writeMappedError(writer, request, ErrUnauthenticated)
		return
	}
	if !principal.Valid() {
		handler.writeMappedError(writer, request, ErrPermissionDenied)
		return
	}
	now := handler.now().UTC().Truncate(time.Microsecond)
	expiresAt, err := parseExpiry(body.ExpiresAt, now, handler.maxTTL)
	if err != nil {
		handler.writeMappedError(writer, request, err)
		return
	}
	digest, err := requestDigest(principal, body, expiresAt, request.Header.Get("Idempotency-Key"), request.Header.Get("X-Request-ID"))
	if err != nil {
		handler.writeMappedError(writer, request, ErrInvalidRequest)
		return
	}
	resolved, err := handler.resolver.Resolve(request.Context(), EvidenceResolveRequest{
		WorkloadID: principal.WorkloadID, Audience: principal.Audience,
		Kind: body.Kind, EvidenceReference: body.EvidenceReference, ExpiresAt: expiresAt,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		RequestDigest: digest,
	})
	if err != nil {
		handler.writeMappedError(writer, request, err)
		return
	}
	if !resolved.bindingsMatch(body.Kind, expiresAt, digest) {
		handler.writeMappedError(writer, request, ErrEvidenceInvalid)
		return
	}
	issueResult, err := handler.issuer.IssuePrincipal(request.Context(), resolved.Principal, identityverificationhttp.RuntimeEvidenceIssueRequest{
		Kind: body.Kind, PrivateObjectReference: resolved.PrivateObjectReference,
		PrivateEnvelopeDigest: resolved.PrivateEnvelopeDigest, EvidenceClaimDigest: resolved.EvidenceClaimDigest,
		Evidence: resolved.Evidence, ExpiresAt: expiresAt, RequestID: request.Header.Get("X-Request-ID"),
		IssuerWorkloadID: principal.WorkloadID, IssuerCertificateFingerprint: principal.CertificateFingerprint,
		IssuerIdempotencyKey: request.Header.Get("Idempotency-Key"), IssuerRequestDigest: digest,
	})
	clearResolvedEvidence(&resolved)
	if err != nil {
		handler.writeMappedError(writer, request, err)
		return
	}
	if !validIssueResult(issueResult, resolved.EvidenceClaimDigest, expiresAt) {
		handler.writeMappedError(writer, request, ErrEvidenceUnavailable)
		return
	}
	handler.writeJSON(writer, http.StatusCreated, issueResponse{
		Token: issueResult.Token, ResolverReference: issueResult.ResolverReference,
		EvidenceDigest: hex.EncodeToString(issueResult.EvidenceClaimDigest[:]), ExpiresAt: issueResult.ExpiresAt,
	})
}

type issueRequest struct {
	Kind              string `json:"kind"`
	EvidenceReference string `json:"evidence_reference"`
	ExpiresAt         string `json:"expires_at"`
}

type issueResponse struct {
	Token             string    `json:"token"`
	ResolverReference string    `json:"resolver_reference"`
	EvidenceDigest    string    `json:"evidence_digest"`
	ExpiresAt         time.Time `json:"expires_at"`
}

func (resolved ResolvedEvidence) bindingsMatch(kind string, expiresAt time.Time, digest [sha256.Size]byte) bool {
	return resolved.Principal.Valid() && resolved.Kind == kind && resolved.Evidence.Kind == kind && resolved.ExpiresAt.Equal(expiresAt) &&
		resolved.RequestDigest == digest && resolved.PrivateObjectReference != "" &&
		resolved.PrivateEnvelopeDigest != ([sha256.Size]byte{}) && resolved.EvidenceClaimDigest != ([sha256.Size]byte{})
}

func validIssueResult(result identityverificationhttp.RuntimeEvidenceIssueResult, claimDigest [sha256.Size]byte, expiresAt time.Time) bool {
	return result.Token != "" && len(result.Token) <= 512 && validOpaque(result.Token) &&
		result.ResolverReference != "" && len(result.ResolverReference) <= 512 && validOpaque(result.ResolverReference) &&
		result.EvidenceRequestDigest != ([sha256.Size]byte{}) && result.EvidenceClaimDigest == claimDigest && result.ExpiresAt.Equal(expiresAt)
}

func parseExpiry(raw string, now time.Time, maxTTL time.Duration) (time.Time, error) {
	if raw == "" || len(raw) > 64 || !utf8.ValidString(raw) {
		return time.Time{}, ErrInvalidRequest
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, ErrInvalidRequest
	}
	parsed = parsed.UTC().Truncate(time.Microsecond)
	if !parsed.After(now) {
		return time.Time{}, ErrEvidenceInvalid
	}
	if parsed.After(now.Add(maxTTL)) {
		return time.Time{}, ErrEvidenceInvalid
	}
	return parsed, nil
}

func validateHeaders(request *http.Request) error {
	for _, name := range []string{"Content-Type", "Idempotency-Key", "X-Request-ID"} {
		if len(request.Header.Values(name)) != 1 {
			return ErrInvalidRequest
		}
	}
	if request.Header.Get("Content-Type") != "application/json" {
		mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || len(params) != 0 {
			return ErrInvalidRequest
		}
		return ErrInvalidRequest
	}
	if !validMetadata(request.Header.Get("Idempotency-Key")) || !validMetadata(request.Header.Get("X-Request-ID")) ||
		len(request.Header.Values("Authorization")) != 0 || len(request.Header.Values("Cookie")) != 0 {
		return ErrUnauthenticated
	}
	for _, name := range []string{"X-Actor-ID", "X-Scope-ID", "X-Tenant-ID", "X-Session-ID", "X-Workload-ID", "X-Audience", "X-Permission"} {
		if len(request.Header.Values(name)) != 0 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func decodeRequestBody(request *http.Request, maxBytes int64) (issueRequest, error) {
	if request.Body == nil {
		return issueRequest{}, ErrInvalidRequest
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
	if err != nil || int64(len(raw)) > maxBytes || !utf8.Valid(raw) || len(raw) == 0 {
		return issueRequest{}, ErrInvalidRequest
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return issueRequest{}, ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var body issueRequest
	if err := decoder.Decode(&body); err != nil {
		return issueRequest{}, ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || body.Kind == "" || !validKind(body.Kind) || !validOpaque(body.EvidenceReference) {
		return issueRequest{}, ErrInvalidRequest
	}
	return body, nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidRequest
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidRequest
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidRequest
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func requestDigest(principal WorkloadPrincipal, body issueRequest, expiresAt time.Time, idempotencyKey, requestID string) ([sha256.Size]byte, error) {
	value := struct {
		WorkloadID, Audience, CertificateFingerprint, Kind, EvidenceReference, ExpiresAt, IdempotencyKey, RequestID string
	}{
		WorkloadID: principal.WorkloadID, Audience: principal.Audience,
		CertificateFingerprint: hex.EncodeToString(principal.CertificateFingerprint[:]), Kind: body.Kind,
		EvidenceReference: body.EvidenceReference, ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
		IdempotencyKey: idempotencyKey, RequestID: requestID,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(append([]byte(requestDigestDomain), encoded...)), nil
}

func validKind(value string) bool {
	return value == identityverification.KindPersonalInitial || value == identityverification.KindPersonalReverification || value == identityverification.KindEnterprise
}

func validOpaque(value string) bool {
	if len(value) == 0 || len(value) > 512 || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsSpace) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:/=@+-", character) {
			continue
		}
		return false
	}
	return true
}

func validMetadata(value string) bool {
	if len(value) == 0 || len(value) > 128 || value != strings.TrimSpace(value) || strings.ContainsFunc(value, unicode.IsSpace) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func hasPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		if permission == required {
			return true
		}
	}
	return false
}

func (handler *Handler) writeMappedError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code := http.StatusServiceUnavailable, CodeEvidenceUnavailable
	switch {
	case errors.Is(err, ErrInvalidRequest):
		status, code = http.StatusBadRequest, CodeInvalidRequest
	case errors.Is(err, ErrUnauthenticated):
		status, code = http.StatusUnauthorized, CodeAuthenticationRequired
	case errors.Is(err, ErrPermissionDenied):
		status, code = http.StatusForbidden, CodePermissionDenied
	case errors.Is(err, ErrEvidenceInvalid), errors.Is(err, identityverificationhttp.ErrInvalidEvidence):
		status, code = http.StatusUnprocessableEntity, CodeEvidenceInvalid
	case errors.Is(err, ErrReplayConflict), errors.Is(err, identityverificationhttp.ErrEvidenceReservationConflict):
		status, code = http.StatusConflict, CodeReplayConflict
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code = http.StatusServiceUnavailable, CodeEvidenceUnavailable
	}
	handler.writeError(writer, request, status, code)
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, status int, code string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	requestID := ""
	if request != nil {
		requestID = request.Header.Get("X-Request-ID")
	}
	payload := struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}{Code: code, RequestID: requestID}}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > handler.maxBodyBytes {
		handler.writeError(writer, nil, http.StatusServiceUnavailable, CodeEvidenceUnavailable)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func clearResolvedEvidence(value *ResolvedEvidence) {
	if value == nil {
		return
	}
	for index := range value.Evidence.Materials {
		clear(value.Evidence.Materials[index].EncryptedEnvelope)
		clear(value.Evidence.Materials[index].ObjectSHA256)
	}
	clear(value.Evidence.SubjectFingerprint)
	clear(value.Evidence.LegalPersonFingerprint)
	clear(value.Evidence.AgentFingerprint)
	value.PrivateObjectReference = ""
}
