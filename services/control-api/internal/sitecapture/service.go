package sitecapture

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	defaultMaxValueBytes = 4096
	defaultMaxBodyBytes  = 64 << 10
	defaultMaxEventBytes = 1 << 20
	maxListEntries       = 128
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var evidencePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Service struct{ store Store }

func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{store: store}, nil
}

func (service *Service) Get(ctx context.Context, actor Actor, scopeID, siteID uuid.UUID) (Policy, error) {
	if err := authorize(actor, scopeID, PermissionRead); err != nil {
		return Policy{}, err
	}
	if siteID == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	policy, err := service.store.Get(ctx, actor, scopeID, siteID)
	if err != nil {
		return Policy{}, err
	}
	if !validPolicy(policy, scopeID, siteID, 1, nil) {
		return Policy{}, ErrUnavailable
	}
	return policy, nil
}

// DefaultDocument is the policy an unconfigured site behaves as: capture off
// with the default byte budgets.
func DefaultDocument() PolicyDocument {
	return PolicyDocument{Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{},
		ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
		MaxValueBytes: defaultMaxValueBytes, MaxBodyBytes: defaultMaxBodyBytes, MaxEventBytes: defaultMaxEventBytes}
}

func (service *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if err := authorize(actor, request.ScopeID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.SiteID == uuid.Nil || request.ExpectedRevision < 0 || !metadataPattern.MatchString(request.IdempotencyKey) ||
		!metadataPattern.MatchString(request.RequestID) || !metadataPattern.MatchString(request.TraceID) {
		return WriteResult{}, ErrInvalidInput
	}
	document, err := canonicalDocument(request.Document)
	if err != nil {
		return WriteResult{}, err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	request.Document = document
	audit := AuditFact{
		Action: AuditActionSet, ActorUserID: actor.UserID, ScopeID: request.ScopeID, SiteID: request.SiteID,
		ExpectedRevision: request.ExpectedRevision, RequestID: request.RequestID, TraceID: request.TraceID,
		DocumentSHA256: digest,
	}
	result, err := service.store.CompareAndSwap(ctx, actor, request, digest, audit)
	if err != nil {
		return WriteResult{}, err
	}
	if !validPolicy(result.Policy, request.ScopeID, request.SiteID, request.ExpectedRevision+1, &digest) {
		return WriteResult{}, ErrUnavailable
	}
	return result, nil
}

func authorize(actor Actor, scopeID uuid.UUID, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrUnauthenticated
	}
	if scopeID == uuid.Nil {
		return ErrInvalidInput
	}
	switch actor.ScopeKind {
	case "tenant":
		if actor.ScopeID != scopeID {
			return ErrNotFound
		}
		if !hasPermission(actor.Permissions, permission) {
			return ErrPermissionDenied
		}
	case "platform":
		if !hasPermission(actor.Permissions, "platform.admin") {
			return ErrPermissionDenied
		}
	default:
		return ErrPermissionDenied
	}
	return nil
}

func validPolicy(policy Policy, scopeID, siteID uuid.UUID, minimumRevision int64, expectedDigest *[32]byte) bool {
	canonical, err := canonicalDocument(policy.Document)
	if err != nil || !reflect.DeepEqual(canonical, policy.Document) || policy.ScopeID != scopeID || policy.SiteID != siteID ||
		policy.Revision < minimumRevision || !evidencePattern.MatchString(policy.EvidenceDigest) {
		return false
	}
	encoded, err := json.Marshal(canonical)
	provided, decodeErr := hex.DecodeString(policy.EvidenceDigest)
	computed := sha256.Sum256(encoded)
	if err != nil || decodeErr != nil || subtle.ConstantTimeCompare(provided, computed[:]) != 1 {
		return false
	}
	return expectedDigest == nil || subtle.ConstantTimeCompare(computed[:], expectedDigest[:]) == 1
}

func hasPermission(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func canonicalDocument(document PolicyDocument) (PolicyDocument, error) {
	var err error
	if document.Methods, err = canonicalMethods(document.Methods); err != nil {
		return PolicyDocument{}, err
	}
	if document.URIPrefixes, err = canonicalPrefixes(document.URIPrefixes); err != nil {
		return PolicyDocument{}, err
	}
	if document.RequestHeaderAllowlist, err = canonicalNames(document.RequestHeaderAllowlist, true); err != nil {
		return PolicyDocument{}, err
	}
	if document.ResponseHeaderAllowlist, err = canonicalNames(document.ResponseHeaderAllowlist, true); err != nil {
		return PolicyDocument{}, err
	}
	if document.RequestBodyFieldAllowlist, err = canonicalNames(document.RequestBodyFieldAllowlist, false); err != nil {
		return PolicyDocument{}, err
	}
	if document.ResponseBodyFieldAllowlist, err = canonicalNames(document.ResponseBodyFieldAllowlist, false); err != nil {
		return PolicyDocument{}, err
	}
	if document.MaxValueBytes == 0 {
		document.MaxValueBytes = defaultMaxValueBytes
	}
	if document.MaxBodyBytes == 0 {
		document.MaxBodyBytes = defaultMaxBodyBytes
	}
	if document.MaxEventBytes == 0 {
		document.MaxEventBytes = defaultMaxEventBytes
	}
	captures := len(document.RequestHeaderAllowlist) + len(document.ResponseHeaderAllowlist) +
		len(document.RequestBodyFieldAllowlist) + len(document.ResponseBodyFieldAllowlist)
	if document.MaxValueBytes < 1 || document.MaxValueBytes > 16<<10 ||
		document.MaxBodyBytes < 1 || document.MaxBodyBytes > 1<<20 ||
		document.MaxEventBytes < 256 || document.MaxEventBytes > 1<<20 ||
		document.Enabled && captures == 0 || !document.Enabled &&
		(captures != 0 || len(document.Methods) != 0 || len(document.URIPrefixes) != 0) {
		return PolicyDocument{}, ErrInvalidInput
	}
	return document, nil
}

func canonicalMethods(values []string) ([]string, error) {
	allowed := map[string]bool{
		http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
		http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	if len(values) > maxListEntries {
		return nil, ErrInvalidInput
	}
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || !ascii(value) {
			return nil, ErrInvalidInput
		}
		value = strings.ToUpper(value)
		if !allowed[value] {
			return nil, ErrInvalidInput
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func canonicalPrefixes(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	if len(values) > maxListEntries {
		return nil, ErrInvalidInput
	}
	for _, value := range values {
		if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
			value[0] != '/' || strings.ContainsAny(value, "?#\r\n\x00") {
			return nil, ErrInvalidInput
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func canonicalNames(values []string, headers bool) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	if len(values) > maxListEntries {
		return nil, ErrInvalidInput
	}
	for _, value := range values {
		if headers {
			value = http.CanonicalHeaderKey(value)
		}
		if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
			strings.ContainsAny(value, "\r\n\x00") || headers && !validHeader(value) {
			return nil, ErrInvalidInput
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result, nil
}

func validHeader(value string) bool {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func ascii(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}
