package errorpagepublicationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxRequestBytes = 64 << 10

var (
	errInvalidRequest  = errors.New("invalid error page publication request")
	errInvalidResponse = errors.New("invalid error page publication response")
	errInvalidConfig   = errors.New("invalid error page publication runtime configuration")
	errMethod          = errors.New("error page publication method not allowed")
	errUnavailable     = errors.New("error page publication unavailable")
	errOutcomeUnknown  = errors.New("error page publication outcome unknown")

	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ifMatchPattern     = regexp.MustCompile(`^"([1-9][0-9]*)"$`)
	tracePattern       = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

type RuntimeDependencies struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	IAM       *iamlock.Authorizer
	Publisher *edgepublish.ErrorPagePublisher
}

func NewRuntimeHandler(dependencies RuntimeDependencies) (http.Handler, error) {
	if !poolConfigured(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Publisher == nil {
		return nil, errInvalidConfig
	}
	return newHandler(
		dependencies.Publisher,
		&runtimePublicationReader{pool: dependencies.Pool, authorizer: dependencies.IAM},
		&runtimeSessionAuthenticator{service: dependencies.Identity},
		&runtimeTenantScopeResolver{pool: dependencies.Pool},
	)
}

type publicationPublisher interface {
	Publish(context.Context, edgepublish.ErrorPagePublishRequest) (edgepublish.ErrorPagePublishResult, error)
}

type publicationReadRequest struct {
	Session       identity.AuthenticatedSession
	RawToken      string
	TenantID      uuid.UUID
	TenantScopeID uuid.UUID
	PublicationID uuid.UUID
}

func (publicationReadRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("errorpagepublicationhttp.publicationReadRequest{session:redacted}"))
}

func (publicationReadRequest) String() string {
	return "errorpagepublicationhttp.publicationReadRequest{session:redacted}"
}

func (publicationReadRequest) GoString() string {
	return "errorpagepublicationhttp.publicationReadRequest{session:redacted}"
}

type publicationReader interface {
	Get(context.Context, publicationReadRequest) (edgepublish.ErrorPagePublishResult, error)
}

type sessionAuthenticator interface {
	Authenticate(context.Context, string) (identity.AuthenticatedSession, error)
}

type tenantScopeResolver interface {
	Resolve(context.Context, identity.Principal, uuid.UUID) (uuid.UUID, error)
}

type Handler struct {
	publisher     publicationPublisher
	reader        publicationReader
	authenticator sessionAuthenticator
	scopes        tenantScopeResolver
	routes        *http.ServeMux
}

func newHandler(
	publisher publicationPublisher,
	reader publicationReader,
	authenticator sessionAuthenticator,
	scopes tenantScopeResolver,
) (*Handler, error) {
	if nilPort(publisher) || nilPort(reader) || nilPort(authenticator) || nilPort(scopes) {
		return nil, errInvalidConfig
	}
	handler := &Handler{publisher: publisher, reader: reader, authenticator: authenticator, scopes: scopes, routes: http.NewServeMux()}
	handler.routes.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/error-page-publications", handler.collection)
	handler.routes.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/error-page-publications/{publication_id}", handler.item)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Request-ID", responseRequestID(request))
	handler.routes.ServeHTTP(response, request)
}

type publishBody struct {
	Target      publishTarget      `json:"target"`
	HealthCheck healthCheckRequest `json:"health_check"`
	MaxAttempts uint32             `json:"max_attempts"`
	Deadline    string             `json:"deadline"`
}

type publishTarget struct {
	Kind           string   `json:"kind"`
	NodeIDs        []string `json:"node_ids,omitempty"`
	SnapshotID     string   `json:"snapshot_id,omitempty"`
	Revision       int64    `json:"revision,omitempty"`
	ResolverSHA256 string   `json:"resolver_sha256,omitempty"`
}

type healthCheckRequest struct {
	ActivationTimeoutMS          int64  `json:"activation_timeout_ms"`
	ObservationWindowMS          int64  `json:"observation_window_ms"`
	RequiredConsecutiveSuccesses uint32 `json:"required_consecutive_successes"`
}

type writeMetadata struct {
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
	Traceparent    string
	TaskID         *string
	IfMatch        string
	SourceRevision int64
	BodySHA256     string
}

type targetView struct {
	Kind           string     `json:"kind"`
	SnapshotID     *uuid.UUID `json:"snapshot_id,omitempty"`
	Revision       *int64     `json:"revision,omitempty"`
	ResolverSHA256 string     `json:"resolver_sha256,omitempty"`
	ResolvedSHA256 string     `json:"resolved_sha256"`
}

type publicationView struct {
	TenantID                     uuid.UUID  `json:"tenant_id"`
	TenantScopeID                uuid.UUID  `json:"tenant_scope_id"`
	PublicationID                uuid.UUID  `json:"publication_id"`
	SourceRevision               int64      `json:"source_revision"`
	ErrorPagePublicationRevision uint64     `json:"error_page_publication_revision"`
	ConfigVersionID              uuid.UUID  `json:"config_version_id"`
	RolloutID                    uuid.UUID  `json:"rollout_id"`
	ArtifactSHA256               string     `json:"artifact_sha256"`
	Target                       targetView `json:"target"`
	NodeCount                    int        `json:"node_count"`
	CreatedAt                    string     `json:"created_at"`
	Replayed                     bool       `json:"replayed,omitempty"`
}

type retryBinding struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	IfMatch        string `json:"if_match"`
	IdempotencyKey string `json:"idempotency_key"`
	BodySHA256     string `json:"body_sha256"`
}

type apiError struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	RequestID string        `json:"request_id"`
	Retry     *retryBinding `json:"retry,omitempty"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

func (handler *Handler) collection(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		handler.writeError(response, request, errMethod, nil)
		return
	}
	if request.URL.RawQuery != "" {
		handler.writeError(response, request, errInvalidRequest, nil)
		return
	}
	session, rawToken, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	if session.Principal.ScopeKind != edgepublish.ScopeKindPlatform {
		handler.writeError(response, request, edgepublish.ErrPermissionDenied, nil)
		return
	}
	scopeID, err := strictUUID(request.PathValue("tenant_scope_id"))
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	tenantID, err := handler.scopes.Resolve(request.Context(), session.Principal, scopeID)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	metadata, body, err := parsePublishRequest(response, request)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	input, err := normalizePublishBody(body)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	actor, err := edgepublish.NewSessionActor(
		session.Principal.UserID, session.Principal.ScopeID, session.Principal.ScopeKind, session.SessionID, rawToken,
	)
	if err != nil {
		handler.writeError(response, request, edgepublish.ErrUnauthenticated, nil)
		return
	}
	result, err := handler.publisher.Publish(request.Context(), edgepublish.ErrorPagePublishRequest{
		TenantID: tenantID,
		PublishRequest: edgepublish.PublishRequest{
			Actor: actor, ConfigurationScopeID: scopeID, ExpectedSourceRevision: metadata.SourceRevision,
			NodeIDs: input.NodeIDs, TargetSnapshot: input.TargetSnapshot, HealthCheck: input.HealthCheck,
			MaxAttempts: input.MaxAttempts, Deadline: input.Deadline, IdempotencyKey: metadata.IdempotencyKey,
			RequestID: metadata.RequestID, CorrelationID: metadata.CorrelationID,
			Traceparent: metadata.Traceparent, TaskID: input.TaskID(metadata.TaskID),
		},
	})
	if err != nil {
		if errors.Is(err, edgepublish.ErrPersistence) {
			retry := &retryBinding{Method: http.MethodPost, Path: request.URL.Path, IfMatch: metadata.IfMatch,
				IdempotencyKey: metadata.IdempotencyKey, BodySHA256: metadata.BodySHA256}
			response.Header().Set("Retry-After", "1")
			handler.writeError(response, request, errOutcomeUnknown, retry)
			return
		}
		handler.writeError(response, request, err, nil)
		return
	}
	view, err := newPublicationView(result, tenantID, scopeID, metadata.SourceRevision)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	if result.Replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
	response.Header().Set("Location", request.URL.Path+"/"+result.PublicationID.String())
	response.Header().Set("ETag", artifactETag(result.ArtifactSHA256))
	writeJSON(response, http.StatusCreated, view)
}

type normalizedPublishBody struct {
	NodeIDs        []uuid.UUID
	TargetSnapshot *edgepublish.TargetSnapshotReference
	HealthCheck    edgedeployment.HealthCheckPolicy
	MaxAttempts    uint32
	Deadline       time.Time
}

func (body normalizedPublishBody) TaskID(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (handler *Handler) item(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeError(response, request, errMethod, nil)
		return
	}
	if request.URL.RawQuery != "" || request.ContentLength > 0 {
		handler.writeError(response, request, errInvalidRequest, nil)
		return
	}
	session, rawToken, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	scopeID, scopeErr := strictUUID(request.PathValue("tenant_scope_id"))
	publicationID, publicationErr := strictUUID(request.PathValue("publication_id"))
	if scopeErr != nil || publicationErr != nil {
		handler.writeError(response, request, errInvalidRequest, nil)
		return
	}
	tenantID, err := handler.scopes.Resolve(request.Context(), session.Principal, scopeID)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	result, err := handler.reader.Get(request.Context(), publicationReadRequest{
		Session: session, RawToken: rawToken, TenantID: tenantID, TenantScopeID: scopeID, PublicationID: publicationID,
	})
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	view, err := newPublicationView(result, tenantID, scopeID, 0)
	if err != nil || view.PublicationID != publicationID {
		handler.writeError(response, request, errInvalidResponse, nil)
		return
	}
	response.Header().Set("ETag", artifactETag(result.ArtifactSHA256))
	writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) authenticate(response http.ResponseWriter, request *http.Request) (identity.AuthenticatedSession, string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		handler.writeError(response, request, edgepublish.ErrUnauthenticated, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	scheme, rawToken, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawToken = strings.TrimSpace(rawToken)
	if !found || !strings.EqualFold(scheme, "Bearer") || rawToken == "" || len(rawToken) > 8192 || strings.ContainsAny(rawToken, " \t\r\n") {
		handler.writeError(response, request, edgepublish.ErrUnauthenticated, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	session, err := handler.authenticator.Authenticate(request.Context(), rawToken)
	if err != nil || !validSession(session) {
		if err == nil {
			err = edgepublish.ErrUnauthenticated
		}
		handler.writeError(response, request, err, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	return session, rawToken, true
}

func parsePublishRequest(response http.ResponseWriter, request *http.Request) (writeMetadata, publishBody, error) {
	metadata, err := parseWriteMetadata(request)
	if err != nil {
		return writeMetadata{}, publishBody{}, err
	}
	contentType, err := singleHeader(request, "Content-Type", true)
	if err != nil {
		return writeMetadata{}, publishBody{}, errInvalidRequest
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return writeMetadata{}, publishBody{}, errInvalidRequest
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || edgeconfig.RejectDuplicateJSONKeys(raw) != nil {
		return writeMetadata{}, publishBody{}, errInvalidRequest
	}
	metadata.BodySHA256 = hexDigest(sha256.Sum256(raw))
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var body publishBody
	if decoder.Decode(&body) != nil || requireJSONEOF(decoder) != nil {
		return writeMetadata{}, publishBody{}, errInvalidRequest
	}
	return metadata, body, nil
}

func parseWriteMetadata(request *http.Request) (writeMetadata, error) {
	ifMatch, err := singleHeader(request, "If-Match", true)
	if err != nil {
		return writeMetadata{}, errInvalidRequest
	}
	matches := ifMatchPattern.FindStringSubmatch(ifMatch)
	if len(matches) != 2 {
		return writeMetadata{}, errInvalidRequest
	}
	revision, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || revision < 1 {
		return writeMetadata{}, errInvalidRequest
	}
	idempotencyKey, err := singleHeader(request, "Idempotency-Key", true)
	if err != nil || !idempotencyPattern.MatchString(idempotencyKey) {
		return writeMetadata{}, errInvalidRequest
	}
	requestID, err := singleHeader(request, "X-Request-ID", true)
	if err != nil {
		return writeMetadata{}, errInvalidRequest
	}
	parsedRequestID, err := strictUUID(requestID)
	if err != nil {
		return writeMetadata{}, errInvalidRequest
	}
	correlationID, err := singleHeader(request, "X-Correlation-ID", false)
	if err != nil {
		return writeMetadata{}, errInvalidRequest
	}
	if correlationID == "" {
		correlationID = parsedRequestID.String()
	} else if parsed, parseErr := strictUUID(correlationID); parseErr != nil {
		return writeMetadata{}, errInvalidRequest
	} else {
		correlationID = parsed.String()
	}
	traceparent, err := singleHeader(request, "Traceparent", true)
	if err != nil || !validTraceparent(traceparent) {
		return writeMetadata{}, errInvalidRequest
	}
	taskID, err := singleHeader(request, "X-Task-ID", false)
	if err != nil || taskID != "" && !metadataPattern.MatchString(taskID) {
		return writeMetadata{}, errInvalidRequest
	}
	var task *string
	if taskID != "" {
		task = &taskID
	}
	return writeMetadata{IdempotencyKey: idempotencyKey, RequestID: parsedRequestID.String(), CorrelationID: correlationID,
		Traceparent: traceparent, TaskID: task, IfMatch: ifMatch, SourceRevision: revision}, nil
}

func normalizePublishBody(body publishBody) (normalizedPublishBody, error) {
	if body.MaxAttempts == 0 || body.MaxAttempts > 10 || body.HealthCheck.ActivationTimeoutMS < 1 ||
		body.HealthCheck.ActivationTimeoutMS > 300000 || body.HealthCheck.ObservationWindowMS < 1 ||
		body.HealthCheck.ObservationWindowMS > 300000 || body.HealthCheck.RequiredConsecutiveSuccesses == 0 ||
		body.HealthCheck.RequiredConsecutiveSuccesses > 100 {
		return normalizedPublishBody{}, errInvalidRequest
	}
	deadline, err := time.Parse(time.RFC3339Nano, body.Deadline)
	if err != nil || deadline.IsZero() {
		return normalizedPublishBody{}, errInvalidRequest
	}
	result := normalizedPublishBody{HealthCheck: edgedeployment.HealthCheckPolicy{
		ActivationTimeout:            time.Duration(body.HealthCheck.ActivationTimeoutMS) * time.Millisecond,
		ObservationWindow:            time.Duration(body.HealthCheck.ObservationWindowMS) * time.Millisecond,
		RequiredConsecutiveSuccesses: body.HealthCheck.RequiredConsecutiveSuccesses,
	}, MaxAttempts: body.MaxAttempts, Deadline: deadline.UTC()}
	switch body.Target.Kind {
	case "nodes":
		if len(body.Target.NodeIDs) == 0 || len(body.Target.NodeIDs) > 10000 || body.Target.SnapshotID != "" ||
			body.Target.Revision != 0 || body.Target.ResolverSHA256 != "" {
			return normalizedPublishBody{}, errInvalidRequest
		}
		result.NodeIDs = make([]uuid.UUID, len(body.Target.NodeIDs))
		for index, raw := range body.Target.NodeIDs {
			result.NodeIDs[index], err = strictUUID(raw)
			if err != nil {
				return normalizedPublishBody{}, errInvalidRequest
			}
		}
		sorted := slices.Clone(result.NodeIDs)
		slices.SortFunc(sorted, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
		if len(slices.Compact(sorted)) != len(result.NodeIDs) {
			return normalizedPublishBody{}, errInvalidRequest
		}
	case "line_group_snapshot":
		if len(body.Target.NodeIDs) != 0 || body.Target.Revision < 1 {
			return normalizedPublishBody{}, errInvalidRequest
		}
		snapshotID, parseErr := strictUUID(body.Target.SnapshotID)
		digest, digestErr := parseSHA256(body.Target.ResolverSHA256)
		if parseErr != nil || digestErr != nil {
			return normalizedPublishBody{}, errInvalidRequest
		}
		result.TargetSnapshot = &edgepublish.TargetSnapshotReference{ID: snapshotID, Revision: body.Target.Revision, SHA256: digest}
	default:
		return normalizedPublishBody{}, errInvalidRequest
	}
	return result, nil
}

func newPublicationView(
	result edgepublish.ErrorPagePublishResult,
	tenantID, scopeID uuid.UUID,
	expectedSourceRevision int64,
) (publicationView, error) {
	bindingTenant, tenantErr := strictUUID(result.Binding.TenantID)
	bindingScope, scopeErr := strictUUID(result.Binding.ConfigurationScopeID)
	if tenantID == uuid.Nil || scopeID == uuid.Nil || tenantErr != nil || scopeErr != nil || bindingTenant != tenantID || bindingScope != scopeID ||
		result.Binding.PublicationRevision == 0 || result.PublicationID == uuid.Nil || result.ConfigurationScopeID != scopeID ||
		result.SourceRevision < 1 || expectedSourceRevision > 0 && result.SourceRevision != expectedSourceRevision ||
		result.ConfigVersionID == uuid.Nil || result.RolloutID == uuid.Nil || result.NodeCount < 1 || result.CreatedAt.IsZero() ||
		result.CanonicalSnapshotSHA256 == ([sha256.Size]byte{}) || result.ArtifactSHA256 == ([sha256.Size]byte{}) ||
		result.CanonicalSnapshotSHA256 != result.ArtifactSHA256 || result.TargetSnapshotSHA256 == ([sha256.Size]byte{}) {
		return publicationView{}, errInvalidResponse
	}
	target := targetView{Kind: result.TargetKind, ResolvedSHA256: hexDigest(result.TargetSnapshotSHA256)}
	switch result.TargetKind {
	case edgepublish.TargetKindExplicit:
		if result.TargetSnapshot != nil {
			return publicationView{}, errInvalidResponse
		}
	case edgepublish.TargetKindResolver:
		if result.TargetSnapshot == nil || result.TargetSnapshot.ID == uuid.Nil || result.TargetSnapshot.Revision < 1 ||
			result.TargetSnapshot.SHA256 == ([sha256.Size]byte{}) {
			return publicationView{}, errInvalidResponse
		}
		id, revision := result.TargetSnapshot.ID, result.TargetSnapshot.Revision
		target.SnapshotID, target.Revision = &id, &revision
		target.ResolverSHA256 = hexDigest(result.TargetSnapshot.SHA256)
	default:
		return publicationView{}, errInvalidResponse
	}
	return publicationView{TenantID: tenantID, TenantScopeID: scopeID, PublicationID: result.PublicationID,
		SourceRevision: result.SourceRevision, ErrorPagePublicationRevision: result.Binding.PublicationRevision,
		ConfigVersionID: result.ConfigVersionID, RolloutID: result.RolloutID,
		ArtifactSHA256: hexDigest(result.ArtifactSHA256), Target: target, NodeCount: result.NodeCount,
		CreatedAt: result.CreatedAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed}, nil
}

type runtimeSessionAuthenticator struct{ service *identity.Service }

func (authenticator *runtimeSessionAuthenticator) Authenticate(ctx context.Context, rawToken string) (identity.AuthenticatedSession, error) {
	if authenticator == nil || authenticator.service == nil || ctx == nil {
		return identity.AuthenticatedSession{}, edgepublish.ErrUnauthenticated
	}
	session, err := authenticator.service.AuthenticateSession(ctx, rawToken)
	if errors.Is(err, identity.ErrInvalidSession) {
		return identity.AuthenticatedSession{}, edgepublish.ErrUnauthenticated
	}
	if err != nil {
		if ctx.Err() != nil {
			return identity.AuthenticatedSession{}, ctx.Err()
		}
		return identity.AuthenticatedSession{}, errUnavailable
	}
	return session, nil
}

type runtimeTenantScopeResolver struct{ pool *pgxpool.Pool }

func (resolver *runtimeTenantScopeResolver) Resolve(ctx context.Context, principal identity.Principal, scopeID uuid.UUID) (uuid.UUID, error) {
	if resolver == nil || resolver.pool == nil || ctx == nil || scopeID == uuid.Nil || !validPrincipal(principal) {
		return uuid.Nil, edgepublish.ErrPermissionDenied
	}
	if principal.ScopeKind == edgepublish.ScopeKindTenant && principal.ScopeID != scopeID {
		return uuid.Nil, edgepublish.ErrPermissionDenied
	}
	var tenantID uuid.UUID
	var active bool
	err := resolver.pool.QueryRow(ctx, `SELECT scope.tenant_id,tenant.status='active'
		FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.id=$1 AND scope.kind='tenant'`, scopeID).Scan(&tenantID, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		if principal.ScopeKind == edgepublish.ScopeKindTenant {
			return uuid.Nil, edgepublish.ErrPermissionDenied
		}
		return uuid.Nil, edgepublish.ErrNotFound
	}
	if err != nil {
		if ctx.Err() != nil {
			return uuid.Nil, ctx.Err()
		}
		return uuid.Nil, errUnavailable
	}
	if !active || tenantID == uuid.Nil || principal.ScopeKind == edgepublish.ScopeKindTenant &&
		(principal.TenantID == nil || *principal.TenantID != tenantID) {
		return uuid.Nil, edgepublish.ErrPermissionDenied
	}
	return tenantID, nil
}

type runtimePublicationReader struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
}

func (reader *runtimePublicationReader) Get(ctx context.Context, request publicationReadRequest) (edgepublish.ErrorPagePublishResult, error) {
	if reader == nil || reader.pool == nil || reader.authorizer == nil || ctx == nil || !validSession(request.Session) ||
		request.RawToken == "" || request.TenantID == uuid.Nil || request.TenantScopeID == uuid.Nil || request.PublicationID == uuid.Nil {
		return edgepublish.ErrorPagePublishResult{}, errInvalidRequest
	}
	var result edgepublish.ErrorPagePublishResult
	err := pgx.BeginFunc(ctx, reader.pool, func(tx pgx.Tx) error {
		authorization, err := reader.authorizer.AuthorizeSession(ctx, tx, request.RawToken, request.TenantScopeID, edgepublish.PermissionRead)
		if err != nil {
			return mapAuthorizationError(ctx, err)
		}
		authorizedTenant, hasTenant := authorization.TenantID()
		if !authorization.Valid() || !hasTenant || authorizedTenant != request.TenantID ||
			authorization.UserID() != request.Session.Principal.UserID ||
			authorization.AuthenticationScopeID() != request.Session.Principal.ScopeID ||
			authorization.TargetScopeID() != request.TenantScopeID || authorization.CredentialKind() != "session" ||
			authorization.CredentialID() != request.Session.SessionID {
			return edgepublish.ErrPermissionDenied
		}
		var snapshotDigest, artifactDigest, targetDigest, resolverDigest, artifactWire, storedArtifactDigest []byte
		var targetID *uuid.UUID
		var targetRevision *int64
		var mediaType string
		err = tx.QueryRow(ctx, `SELECT publication.id,publication.source_revision,
			publication.canonical_snapshot_sha256,publication.artifact_sha256,
			publication.config_version_id,publication.rollout_id,publication.node_count,publication.created_at,
			publication.target_kind,publication.target_snapshot_id,publication.target_snapshot_revision,
			publication.target_resolver_sha256,publication.target_snapshot_sha256,
			artifact.wire_bytes,artifact.sha256,artifact.media_type
			FROM edge_config_publications publication
			JOIN configuration_artifacts artifact ON artifact.config_version_id=publication.config_version_id
			 AND artifact.ordinal=1 AND artifact.kind='configuration'
			 AND artifact.media_type=$3
			WHERE publication.configuration_scope_id=$1 AND publication.id=$2`,
			request.TenantScopeID, request.PublicationID, errorpagecontrol.ProductionSnapshotMediaType).Scan(
			&result.PublicationID, &result.SourceRevision, &snapshotDigest, &artifactDigest,
			&result.ConfigVersionID, &result.RolloutID, &result.NodeCount, &result.CreatedAt,
			&result.TargetKind, &targetID, &targetRevision, &resolverDigest, &targetDigest,
			&artifactWire, &storedArtifactDigest, &mediaType)
		if errors.Is(err, pgx.ErrNoRows) {
			return edgepublish.ErrNotFound
		}
		if err != nil {
			return errUnavailable
		}
		result.ConfigurationScopeID = request.TenantScopeID
		if !copyDigest(&result.CanonicalSnapshotSHA256, snapshotDigest) || !copyDigest(&result.ArtifactSHA256, artifactDigest) ||
			!copyDigest(&result.TargetSnapshotSHA256, targetDigest) || mediaType != errorpagecontrol.ProductionSnapshotMediaType {
			return errInvalidResponse
		}
		if targetID != nil || targetRevision != nil || len(resolverDigest) != 0 {
			if targetID == nil || targetRevision == nil {
				return errInvalidResponse
			}
			result.TargetSnapshot = &edgepublish.TargetSnapshotReference{ID: *targetID, Revision: *targetRevision}
			if !copyDigest(&result.TargetSnapshot.SHA256, resolverDigest) {
				return errInvalidResponse
			}
		}
		binding, err := decodeArtifactBinding(artifactWire, storedArtifactDigest, result.ArtifactSHA256)
		if err != nil {
			return err
		}
		result.Binding = binding
		return nil
	})
	if err != nil {
		return edgepublish.ErrorPagePublishResult{}, err
	}
	return result, nil
}

func decodeArtifactBinding(raw, storedDigest []byte, publicationDigest [sha256.Size]byte) (errorpagecontrol.ProductionSnapshotBinding, error) {
	actual := sha256.Sum256(raw)
	if len(raw) == 0 || len(storedDigest) != sha256.Size || !bytes.Equal(actual[:], storedDigest) || actual != publicationDigest ||
		edgeconfig.RejectDuplicateJSONKeys(raw) != nil {
		return errorpagecontrol.ProductionSnapshotBinding{}, errInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document errorpagecontrol.ProductionSnapshotDocument
	if decoder.Decode(&document) != nil || requireJSONEOF(decoder) != nil || document.Schema != errorpagecontrol.ProductionSnapshotSchema {
		return errorpagecontrol.ProductionSnapshotBinding{}, errInvalidResponse
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errorpagecontrol.ProductionSnapshotBinding{}, errInvalidResponse
	}
	return document.Binding, nil
}

func mapAuthorizationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return edgepublish.ErrUnauthenticated
	}
	if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
		return edgepublish.ErrPermissionDenied
	}
	return errUnavailable
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error, retry *retryBinding) {
	status, code, message := classifyError(err)
	writeJSON(response, status, errorEnvelope{Error: apiError{
		Code: code, Message: message, RequestID: response.Header().Get("X-Request-ID"), Retry: retry,
	}})
}

func classifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, edgepublish.ErrUnauthenticated), errors.Is(err, identity.ErrInvalidSession):
		return http.StatusUnauthorized, "error_page_publication_unauthenticated", "需要重新登录"
	case errors.Is(err, edgepublish.ErrPermissionDenied):
		return http.StatusForbidden, "error_page_publication_permission_denied", "没有此发布操作的权限"
	case errors.Is(err, errInvalidRequest), errors.Is(err, edgepublish.ErrInvalidInput):
		return http.StatusBadRequest, "error_page_publication_invalid_request", "请求参数无效"
	case errors.Is(err, edgepublish.ErrNotFound):
		return http.StatusNotFound, "error_page_publication_not_found", "未找到错误页发布记录"
	case errors.Is(err, edgepublish.ErrIdempotencyConflict):
		return http.StatusConflict, "error_page_publication_idempotency_conflict", "幂等键已绑定其他请求"
	case errors.Is(err, edgepublish.ErrRevisionConflict):
		return http.StatusPreconditionFailed, "error_page_publication_revision_conflict", "源配置版本已变化"
	case errors.Is(err, edgepublish.ErrTargetSnapshotConflict):
		return http.StatusConflict, "error_page_publication_target_conflict", "目标节点快照已变化"
	case errors.Is(err, edgepublish.ErrTargetIneligible), errors.Is(err, edgedeployment.ErrNodeDeploymentActive):
		return http.StatusUnprocessableEntity, "error_page_publication_target_ineligible", "目标节点当前不可发布"
	case errors.Is(err, edgepublish.ErrEntitlementDenied):
		return http.StatusUnprocessableEntity, "error_page_publication_entitlement_denied", "当前授权不允许发布"
	case errors.Is(err, errInvalidResponse):
		return http.StatusBadGateway, "error_page_publication_invalid_response", "发布结果身份校验失败"
	case errors.Is(err, errOutcomeUnknown):
		return http.StatusServiceUnavailable, "error_page_publication_outcome_unknown", "发布结果未知，请按提示原样重试"
	case errors.Is(err, errMethod):
		return http.StatusMethodNotAllowed, "error_page_publication_method_not_allowed", "请求方法不受支持"
	default:
		return http.StatusServiceUnavailable, "error_page_publication_unavailable", "错误页发布服务暂不可用"
	}
}

func strictUUID(raw string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed == uuid.Nil || parsed.String() != raw {
		return uuid.Nil, errInvalidRequest
	}
	return parsed, nil
}

func parseSHA256(raw string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(raw) != hex.EncodedLen(len(result)) || raw != strings.ToLower(raw) {
		return result, errInvalidRequest
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != len(result) {
		return result, errInvalidRequest
	}
	copy(result[:], decoded)
	if result == ([sha256.Size]byte{}) {
		return result, errInvalidRequest
	}
	return result, nil
}

func singleHeader(request *http.Request, name string, required bool) (string, error) {
	values := request.Header.Values(name)
	if len(values) > 1 || required && len(values) != 1 {
		return "", errInvalidRequest
	}
	if len(values) == 0 {
		return "", nil
	}
	value := values[0]
	if value == "" || strings.TrimSpace(value) != value {
		return "", errInvalidRequest
	}
	return value, nil
}

func validTraceparent(value string) bool {
	matches := tracePattern.FindStringSubmatch(value)
	return len(matches) == 4 && matches[1] != strings.Repeat("0", 32) && matches[2] != strings.Repeat("0", 16)
}

func validSession(session identity.AuthenticatedSession) bool {
	return session.SessionID != uuid.Nil && validPrincipal(session.Principal)
}

func validPrincipal(principal identity.Principal) bool {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return false
	}
	if principal.ScopeKind == edgepublish.ScopeKindPlatform {
		return principal.TenantID == nil
	}
	return principal.ScopeKind == edgepublish.ScopeKindTenant && principal.TenantID != nil && *principal.TenantID != uuid.Nil
}

func responseRequestID(request *http.Request) string {
	if request != nil {
		if values := request.Header.Values("X-Request-ID"); len(values) == 1 {
			if parsed, err := strictUUID(values[0]); err == nil {
				return parsed.String()
			}
		}
	}
	return uuid.NewString()
}

func requireJSONEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func artifactETag(digest [sha256.Size]byte) string { return `"sha256-` + hexDigest(digest) + `"` }
func hexDigest(digest [sha256.Size]byte) string    { return hex.EncodeToString(digest[:]) }

func copyDigest(target *[sha256.Size]byte, value []byte) bool {
	if len(value) != sha256.Size {
		return false
	}
	copy(target[:], value)
	return *target != ([sha256.Size]byte{})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func poolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil && pool.Config().MaxConns > 0
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ publicationPublisher = (*edgepublish.ErrorPagePublisher)(nil)
var _ publicationReader = (*runtimePublicationReader)(nil)
var _ sessionAuthenticator = (*runtimeSessionAuthenticator)(nil)
var _ tenantScopeResolver = (*runtimeTenantScopeResolver)(nil)
