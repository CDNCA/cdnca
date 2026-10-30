package originauthpublicationhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

const (
	maxRequestBytes       = 64 << 10
	generatorName         = "origin-auth-edge-publication"
	generatorVersion      = "v1"
	publicationDigestKind = "cdnca.control.origin-auth-edge-publication-request/v1"
	publicationSchema     = "cdnca.control.originauth-publication/v1"
)

var (
	errInvalidRequest  = errors.New("invalid origin auth edge publication request")
	errInvalidResponse = errors.New("invalid origin auth edge publication response")
	errInvalidConfig   = errors.New("invalid origin auth edge publication runtime configuration")
	errMethod          = errors.New("origin auth edge publication method not allowed")
	errUnavailable     = errors.New("origin auth edge publication unavailable")
	errOutcomeUnknown  = errors.New("origin auth edge publication outcome unknown")
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ifMatchPattern     = regexp.MustCompile(`^"([1-9][0-9]*)"$`)
	tracePattern       = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

type RuntimeDependencies struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	IAM       *iamlock.Authorizer
	Publisher *edgepublish.Runtime
	Source    edgepublish.OriginAuthProductionSource
	Producer  *edgepublish.OriginAuthArtifactProducer
}

func NewRuntimeHandler(dependencies RuntimeDependencies) (http.Handler, error) {
	if !poolConfigured(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Publisher == nil ||
		!dependencies.Publisher.ConfiguredFor(dependencies.Pool, dependencies.IAM) || nilPort(dependencies.Source) ||
		dependencies.Producer == nil || dependencies.Publisher.RolloutCommands() == nil {
		return nil, errInvalidConfig
	}
	return newHandler(
		&runtimePublicationPublisher{pool: dependencies.Pool, deployments: dependencies.Publisher.RolloutCommands(),
			source: dependencies.Source, producer: dependencies.Producer},
		&runtimePublicationReader{pool: dependencies.Pool, authorizer: dependencies.IAM},
		&runtimeSessionAuthenticator{service: dependencies.Identity},
		&runtimeTenantScopeResolver{pool: dependencies.Pool},
	)
}

type publicationRequest struct {
	Actor                  edgedeployment.Actor
	TenantID               uuid.UUID
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	NodeIDs                []uuid.UUID
	HealthCheck            edgedeployment.HealthCheckPolicy
	Deadline               time.Time
	IdempotencyKey         string
	RequestID              string
	CorrelationID          string
	Traceparent            string
	TaskID                 *string
	BodySHA256             [sha256.Size]byte
}

type publicationResult struct {
	TenantID               uuid.UUID
	TenantScopeID          uuid.UUID
	PublicationID          uuid.UUID
	SourcePublicationID    uuid.UUID
	SourceRevision         int64
	ConfigVersionID        uuid.UUID
	RolloutID              uuid.UUID
	ConfigSnapshotSHA256   [sha256.Size]byte
	ArtifactManifestSHA256 [sha256.Size]byte
	RecipientBindingSHA256 [sha256.Size]byte
	NodeCount              int
	CreatedAt              time.Time
	Replayed               bool
}

type publicationPublisher interface {
	Publish(context.Context, publicationRequest) (publicationResult, error)
}

type publicationReadRequest struct {
	Session       identity.AuthenticatedSession
	RawToken      string
	TenantID      uuid.UUID
	TenantScopeID uuid.UUID
	PublicationID uuid.UUID
}

func (publicationReadRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("originauthpublicationhttp.publicationReadRequest{session:redacted}"))
}

func (publicationReadRequest) String() string {
	return "originauthpublicationhttp.publicationReadRequest{session:redacted}"
}

func (publicationReadRequest) GoString() string {
	return "originauthpublicationhttp.publicationReadRequest{session:redacted}"
}

type publicationReader interface {
	Get(context.Context, publicationReadRequest) (publicationResult, error)
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
	handler.routes.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications", handler.collection)
	handler.routes.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications/{publication_id}", handler.item)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Request-ID", responseRequestID(request))
	handler.routes.ServeHTTP(response, request)
}

type publishBody struct {
	NodeIDs     []string           `json:"node_ids"`
	HealthCheck healthCheckRequest `json:"health_check"`
	Deadline    string             `json:"deadline"`
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
	BodySHA256     [sha256.Size]byte
}

type publicationView struct {
	TenantID               uuid.UUID `json:"tenant_id"`
	TenantScopeID          uuid.UUID `json:"tenant_scope_id"`
	PublicationID          uuid.UUID `json:"publication_id"`
	SourcePublicationID    uuid.UUID `json:"source_publication_id"`
	SourceRevision         int64     `json:"source_revision"`
	ConfigVersionID        uuid.UUID `json:"config_version_id"`
	RolloutID              uuid.UUID `json:"rollout_id"`
	ConfigSnapshotSHA256   string    `json:"config_snapshot_sha256"`
	ArtifactManifestSHA256 string    `json:"artifact_manifest_sha256"`
	RecipientBindingSHA256 string    `json:"recipient_binding_sha256"`
	NodeCount              int       `json:"node_count"`
	CreatedAt              string    `json:"created_at"`
	Replayed               bool      `json:"replayed,omitempty"`
}

type retryBinding struct {
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	IfMatch        string  `json:"if_match"`
	IdempotencyKey string  `json:"idempotency_key"`
	BodySHA256     string  `json:"body_sha256"`
	RequestID      string  `json:"request_id"`
	CorrelationID  string  `json:"correlation_id"`
	Traceparent    string  `json:"traceparent"`
	TaskID         *string `json:"task_id,omitempty"`
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
	if session.Principal.ScopeKind != edgedeployment.ScopeKindPlatform {
		handler.writeError(response, request, edgedeployment.ErrPermissionDenied, nil)
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
	normalized, err := normalizePublishBody(body)
	if err != nil {
		handler.writeError(response, request, err, nil)
		return
	}
	actor, err := edgedeployment.NewSessionActor(
		session.Principal.UserID, session.Principal.ScopeID, session.Principal.ScopeKind, session.SessionID, rawToken,
	)
	if err != nil {
		handler.writeError(response, request, edgedeployment.ErrUnauthenticated, nil)
		return
	}
	result, err := handler.publisher.Publish(request.Context(), publicationRequest{
		Actor: actor, TenantID: tenantID, ConfigurationScopeID: scopeID, ExpectedSourceRevision: metadata.SourceRevision,
		NodeIDs: normalized.NodeIDs, HealthCheck: normalized.HealthCheck, Deadline: normalized.Deadline,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID, CorrelationID: metadata.CorrelationID,
		Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID), BodySHA256: metadata.BodySHA256,
	})
	if err != nil {
		if errors.Is(err, errOutcomeUnknown) {
			retry := &retryBinding{Method: http.MethodPost, Path: request.URL.Path, IfMatch: metadata.IfMatch,
				IdempotencyKey: metadata.IdempotencyKey, BodySHA256: hexDigest(metadata.BodySHA256), RequestID: metadata.RequestID,
				CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID)}
			response.Header().Set("Retry-After", "1")
			handler.writeError(response, request, err, retry)
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
	response.Header().Set("ETag", digestETag(result.ArtifactManifestSHA256))
	writeJSON(response, http.StatusCreated, view)
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
	response.Header().Set("ETag", digestETag(result.ArtifactManifestSHA256))
	writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) authenticate(response http.ResponseWriter, request *http.Request) (identity.AuthenticatedSession, string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		handler.writeError(response, request, edgedeployment.ErrUnauthenticated, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	scheme, rawToken, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawToken = strings.TrimSpace(rawToken)
	if !found || !strings.EqualFold(scheme, "Bearer") || rawToken == "" || len(rawToken) > 8192 || strings.ContainsAny(rawToken, " \t\r\n") {
		handler.writeError(response, request, edgedeployment.ErrUnauthenticated, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	session, err := handler.authenticator.Authenticate(request.Context(), rawToken)
	if err != nil || !validSession(session) {
		if err == nil {
			err = edgedeployment.ErrUnauthenticated
		}
		handler.writeError(response, request, err, nil)
		return identity.AuthenticatedSession{}, "", false
	}
	return session, rawToken, true
}

type normalizedPublishBody struct {
	NodeIDs     []uuid.UUID
	HealthCheck edgedeployment.HealthCheckPolicy
	Deadline    time.Time
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
	metadata.BodySHA256 = sha256.Sum256(raw)
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
	metadata := writeMetadata{IdempotencyKey: idempotencyKey, RequestID: parsedRequestID.String(), CorrelationID: correlationID,
		Traceparent: traceparent, IfMatch: ifMatch, SourceRevision: revision}
	if taskID != "" {
		metadata.TaskID = &taskID
	}
	return metadata, nil
}

func normalizePublishBody(body publishBody) (normalizedPublishBody, error) {
	if len(body.NodeIDs) == 0 || len(body.NodeIDs) > 10000 || body.HealthCheck.ActivationTimeoutMS < 1 ||
		body.HealthCheck.ActivationTimeoutMS > 300000 || body.HealthCheck.ObservationWindowMS < 1 ||
		body.HealthCheck.ObservationWindowMS > 300000 || body.HealthCheck.RequiredConsecutiveSuccesses < 1 ||
		body.HealthCheck.RequiredConsecutiveSuccesses > 100 {
		return normalizedPublishBody{}, errInvalidRequest
	}
	nodes := make([]uuid.UUID, len(body.NodeIDs))
	for index, raw := range body.NodeIDs {
		node, err := strictUUID(raw)
		if err != nil {
			return normalizedPublishBody{}, errInvalidRequest
		}
		nodes[index] = node
	}
	slices.SortFunc(nodes, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	if len(slices.Compact(slices.Clone(nodes))) != len(nodes) {
		return normalizedPublishBody{}, errInvalidRequest
	}
	deadline, err := time.Parse(time.RFC3339Nano, body.Deadline)
	if err != nil || deadline.IsZero() {
		return normalizedPublishBody{}, errInvalidRequest
	}
	return normalizedPublishBody{NodeIDs: nodes, HealthCheck: edgedeployment.HealthCheckPolicy{
		ActivationTimeout:            time.Duration(body.HealthCheck.ActivationTimeoutMS) * time.Millisecond,
		ObservationWindow:            time.Duration(body.HealthCheck.ObservationWindowMS) * time.Millisecond,
		RequiredConsecutiveSuccesses: body.HealthCheck.RequiredConsecutiveSuccesses,
	}, Deadline: deadline.UTC()}, nil
}

func newPublicationView(result publicationResult, tenantID, scopeID uuid.UUID, expectedRevision int64) (publicationView, error) {
	if tenantID == uuid.Nil || scopeID == uuid.Nil || result.TenantID != tenantID || result.TenantScopeID != scopeID ||
		result.PublicationID == uuid.Nil || result.PublicationID != result.RolloutID || result.SourcePublicationID == uuid.Nil ||
		result.SourceRevision < 1 || expectedRevision > 0 && result.SourceRevision != expectedRevision ||
		result.ConfigVersionID == uuid.Nil || result.RolloutID == uuid.Nil || result.NodeCount < 1 || result.CreatedAt.IsZero() ||
		result.ConfigSnapshotSHA256 == ([sha256.Size]byte{}) || result.ArtifactManifestSHA256 == ([sha256.Size]byte{}) ||
		result.RecipientBindingSHA256 == ([sha256.Size]byte{}) {
		return publicationView{}, errInvalidResponse
	}
	return publicationView{TenantID: tenantID, TenantScopeID: scopeID, PublicationID: result.PublicationID,
		SourcePublicationID: result.SourcePublicationID, SourceRevision: result.SourceRevision,
		ConfigVersionID: result.ConfigVersionID, RolloutID: result.RolloutID,
		ConfigSnapshotSHA256: hexDigest(result.ConfigSnapshotSHA256), ArtifactManifestSHA256: hexDigest(result.ArtifactManifestSHA256),
		RecipientBindingSHA256: hexDigest(result.RecipientBindingSHA256), NodeCount: result.NodeCount,
		CreatedAt: result.CreatedAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed}, nil
}

type runtimePublicationPublisher struct {
	pool        *pgxpool.Pool
	deployments *edgedeployment.Store
	source      edgepublish.OriginAuthProductionSource
	producer    *edgepublish.OriginAuthArtifactProducer
}

func (publisher *runtimePublicationPublisher) Publish(ctx context.Context, request publicationRequest) (publicationResult, error) {
	if publisher == nil || publisher.pool == nil || publisher.deployments == nil || nilPort(publisher.source) || publisher.producer == nil ||
		ctx == nil || request.TenantID == uuid.Nil || request.ConfigurationScopeID == uuid.Nil || request.ExpectedSourceRevision < 1 ||
		request.BodySHA256 == ([sha256.Size]byte{}) {
		return publicationResult{}, errInvalidRequest
	}
	source, err := edgepublish.NewOriginAuthSecretRolloutSource(request.ConfigurationScopeID,
		&revisionBoundSource{source: publisher.source, tenantID: request.TenantID, scopeID: request.ConfigurationScopeID,
			expectedRevision: request.ExpectedSourceRevision}, publisher.producer)
	if err != nil {
		return publicationResult{}, errInvalidRequest
	}
	domainDigest, err := publicationRequestDigest(request)
	if err != nil {
		return publicationResult{}, errInvalidRequest
	}
	var result publicationResult
	err = pgx.BeginFunc(ctx, publisher.pool, func(tx pgx.Tx) error {
		created, createErr := publisher.deployments.CreateSecretRolloutFromSourceTx(ctx, tx, edgedeployment.SecretRolloutRequest{
			Actor: request.Actor, ConfigurationScopeID: request.ConfigurationScopeID, NodeIDs: slices.Clone(request.NodeIDs),
			GeneratorName: generatorName, GeneratorVersion: generatorVersion, HealthCheck: request.HealthCheck,
			Deadline: request.Deadline, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
			CorrelationID: request.CorrelationID, Traceparent: request.Traceparent, TaskID: cloneString(request.TaskID),
		}, domainDigest, []string{originauthcontrol.PermissionManage}, source)
		if createErr != nil {
			return createErr
		}
		loaded, loadErr := loadPublicationTx(ctx, tx, request.TenantID, request.ConfigurationScopeID, created.Rollout.ID)
		if loadErr != nil {
			return loadErr
		}
		loaded.Replayed = created.Replayed
		result = loaded
		return nil
	})
	if err != nil {
		return publicationResult{}, stablePublishError(ctx, err)
	}
	return result, nil
}

type revisionBoundSource struct {
	source           edgepublish.OriginAuthProductionSource
	tenantID         uuid.UUID
	scopeID          uuid.UUID
	expectedRevision int64
}

func (source *revisionBoundSource) Build(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (originauthcontrol.ProductionMaterial, error) {
	if source == nil || nilPort(source.source) || ctx == nil || tx == nil || scopeID != source.scopeID || source.tenantID == uuid.Nil ||
		source.expectedRevision < 1 {
		return originauthcontrol.ProductionMaterial{}, errInvalidRequest
	}
	material, err := source.source.Build(ctx, tx, scopeID)
	if err != nil {
		return originauthcontrol.ProductionMaterial{}, err
	}
	if material.TenantID != source.tenantID || material.TenantScopeID != source.scopeID ||
		material.PublicationRevision != uint64(source.expectedRevision) {
		clearProductionMaterial(&material)
		return originauthcontrol.ProductionMaterial{}, originauthcontrol.ErrRevisionConflict
	}
	return material, nil
}

func publicationRequestDigest(request publicationRequest) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		Domain         string `json:"domain"`
		TenantID       string `json:"tenant_id"`
		TenantScopeID  string `json:"tenant_scope_id"`
		SourceRevision int64  `json:"source_revision"`
		BodySHA256     string `json:"body_sha256"`
	}{publicationDigestKind, request.TenantID.String(), request.ConfigurationScopeID.String(),
		request.ExpectedSourceRevision, hexDigest(request.BodySHA256)})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

type runtimePublicationReader struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
}

func (reader *runtimePublicationReader) Get(ctx context.Context, request publicationReadRequest) (publicationResult, error) {
	if reader == nil || reader.pool == nil || reader.authorizer == nil || ctx == nil || !validSession(request.Session) ||
		request.RawToken == "" || request.TenantID == uuid.Nil || request.TenantScopeID == uuid.Nil || request.PublicationID == uuid.Nil {
		return publicationResult{}, errInvalidRequest
	}
	var result publicationResult
	err := pgx.BeginFunc(ctx, reader.pool, func(tx pgx.Tx) error {
		for _, permission := range []string{edgepublish.PermissionRead, originauthcontrol.PermissionRead} {
			authorization, err := reader.authorizer.AuthorizeSession(ctx, tx, request.RawToken, request.TenantScopeID, permission)
			if err != nil {
				return mapAuthorizationError(ctx, err)
			}
			if !matchesAuthorization(authorization, request) {
				return edgedeployment.ErrPermissionDenied
			}
		}
		var err error
		result, err = loadPublicationTx(ctx, tx, request.TenantID, request.TenantScopeID, request.PublicationID)
		return err
	})
	if err != nil {
		return publicationResult{}, err
	}
	return result, nil
}

func matchesAuthorization(authorization iamlock.Authorization, request publicationReadRequest) bool {
	tenantID, hasTenant := authorization.TenantID()
	return authorization.Valid() && hasTenant && tenantID == request.TenantID &&
		authorization.UserID() == request.Session.Principal.UserID &&
		authorization.AuthenticationScopeID() == request.Session.Principal.ScopeID &&
		authorization.TargetScopeID() == request.TenantScopeID && authorization.CredentialKind() == "session" &&
		authorization.CredentialID() == request.Session.SessionID
}

type rolloutFacts struct {
	ID, ScopeID, ConfigID, RequestID, CorrelationID uuid.UUID
	Traceparent                                     string
	TaskID                                          *string
	ActivationTimeoutMS, ObservationWindowMS        int64
	RequiredSuccesses                               uint32
	Deadline, CreatedAt                             time.Time
	CanonicalSnapshot, ConfigDigest                 []byte
}

type deploymentFacts struct {
	DeploymentID, NodeID, EventID, ArtifactID  uuid.UUID
	CommandBytes, ArtifactWire, ArtifactSHA256 []byte
	ArtifactSize                               int64
	ArtifactSignature, SigningPublicKey        []byte
	SigningKeyID, SignatureAlgorithm           string
	Compression, MediaType, Encryption         string
	RecipientKeyID                             string
	RecipientPublicKeySHA256                   []byte
}

func loadPublicationTx(ctx context.Context, tx pgx.Tx, tenantID, scopeID, rolloutID uuid.UUID) (publicationResult, error) {
	if ctx == nil || tx == nil || tenantID == uuid.Nil || scopeID == uuid.Nil || rolloutID == uuid.Nil {
		return publicationResult{}, errInvalidRequest
	}
	var facts rolloutFacts
	var maxAttempts, contractVersion int
	err := tx.QueryRow(ctx, `SELECT rollout.id,rollout.configuration_scope_id,rollout.config_version_id,
		rollout.request_id,rollout.correlation_id,rollout.traceparent,rollout.task_id,
		rollout.activation_timeout_ms,rollout.observation_window_ms,rollout.required_consecutive_successes,
		rollout.deadline_at,rollout.created_at,rollout.max_attempts,rollout.contract_version,
		config.canonical_snapshot,config.canonical_snapshot_sha256
		FROM rollouts rollout JOIN config_versions config
		  ON config.configuration_scope_id=rollout.configuration_scope_id AND config.id=rollout.config_version_id
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2 AND rollout.action='apply'
		  AND config.status='releasable' AND config.generator_name=$3 AND config.generator_version=$4`,
		scopeID, rolloutID, generatorName, generatorVersion).Scan(
		&facts.ID, &facts.ScopeID, &facts.ConfigID, &facts.RequestID, &facts.CorrelationID, &facts.Traceparent, &facts.TaskID,
		&facts.ActivationTimeoutMS, &facts.ObservationWindowMS, &facts.RequiredSuccesses, &facts.Deadline, &facts.CreatedAt,
		&maxAttempts, &contractVersion, &facts.CanonicalSnapshot, &facts.ConfigDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return publicationResult{}, edgedeployment.ErrNotFound
	}
	if err != nil {
		return publicationResult{}, errUnavailable
	}
	if facts.ID != rolloutID || facts.ScopeID != scopeID || facts.ConfigID == uuid.Nil || maxAttempts != 1 || contractVersion != 0 ||
		facts.RequestID == uuid.Nil || facts.CorrelationID == uuid.Nil || facts.ActivationTimeoutMS < 1 ||
		facts.ObservationWindowMS < 1 || facts.RequiredSuccesses < 1 || !facts.Deadline.After(facts.CreatedAt) || facts.CreatedAt.IsZero() {
		return publicationResult{}, errInvalidResponse
	}
	configDigest := sha256.Sum256(facts.CanonicalSnapshot)
	if !equalDigest(facts.ConfigDigest, configDigest) || edgeconfig.RejectDuplicateJSONKeys(facts.CanonicalSnapshot) != nil {
		return publicationResult{}, errInvalidResponse
	}
	var snapshot originauthcontrol.PublicationSnapshot
	decoder := json.NewDecoder(bytes.NewReader(facts.CanonicalSnapshot))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || requireJSONEOF(decoder) != nil || snapshot.SchemaVersion != publicationSchema ||
		snapshot.TenantScopeID != scopeID || snapshot.PublicationRevision < 1 || len(snapshot.Rules) == 0 {
		return publicationResult{}, errInvalidResponse
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(canonical, facts.CanonicalSnapshot) {
		return publicationResult{}, errInvalidResponse
	}
	var sourceID, sourceTenantID uuid.UUID
	var sourceDigest []byte
	err = tx.QueryRow(ctx, `SELECT id,tenant_id,snapshot_sha256 FROM origin_auth_publications
		WHERE tenant_scope_id=$1 AND revision=$2 AND canonical_snapshot=$3`,
		scopeID, snapshot.PublicationRevision, facts.CanonicalSnapshot).Scan(&sourceID, &sourceTenantID, &sourceDigest)
	if err != nil || sourceID == uuid.Nil || sourceTenantID != tenantID || !equalDigest(sourceDigest, configDigest) {
		return publicationResult{}, errInvalidResponse
	}
	deployments, err := loadDeploymentFacts(ctx, tx, facts)
	if err != nil {
		return publicationResult{}, err
	}
	defer clearDeploymentFacts(deployments)
	artifactDigest, recipientDigest, err := validateDeploymentFacts(facts, deployments)
	if err != nil {
		return publicationResult{}, err
	}
	return publicationResult{TenantID: tenantID, TenantScopeID: scopeID, PublicationID: rolloutID,
		SourcePublicationID: sourceID, SourceRevision: snapshot.PublicationRevision, ConfigVersionID: facts.ConfigID, RolloutID: rolloutID,
		ConfigSnapshotSHA256: configDigest, ArtifactManifestSHA256: artifactDigest, RecipientBindingSHA256: recipientDigest,
		NodeCount: len(deployments), CreatedAt: facts.CreatedAt}, nil
}

func loadDeploymentFacts(ctx context.Context, tx pgx.Tx, rollout rolloutFacts) ([]deploymentFacts, error) {
	rows, err := tx.Query(ctx, `SELECT deployment.id,deployment.node_id,deployment.command_event_id,deployment.command_bytes,
		artifact.id,artifact.wire_bytes,artifact.size_bytes,artifact.sha256,artifact.signature,
		artifact.signing_key_id,artifact.signature_algorithm,artifact.compression,artifact.media_type,
		artifact.encryption_algorithm,artifact.recipient_key_id,signing.public_key,recipient.public_key_sha256
		FROM node_deployments deployment
		JOIN node_deployment_artifacts binding ON binding.deployment_id=deployment.id
		 AND binding.deployment_attempt=deployment.attempt AND binding.ordinal=1
		JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
		 AND artifact.id=binding.artifact_id AND artifact.ordinal=binding.ordinal
		JOIN artifact_signing_keys signing ON signing.id=artifact.signing_key_id
		JOIN node_artifact_encryption_keys recipient ON recipient.node_id=deployment.node_id
		 AND recipient.id=artifact.recipient_key_id
		WHERE deployment.rollout_id=$1 AND deployment.config_version_id=$2 AND deployment.attempt=1
		 AND deployment.action='apply' ORDER BY deployment.node_id`, rollout.ID, rollout.ConfigID)
	if err != nil {
		return nil, errUnavailable
	}
	defer rows.Close()
	var result []deploymentFacts
	for rows.Next() {
		var value deploymentFacts
		if err := rows.Scan(&value.DeploymentID, &value.NodeID, &value.EventID, &value.CommandBytes,
			&value.ArtifactID, &value.ArtifactWire, &value.ArtifactSize, &value.ArtifactSHA256, &value.ArtifactSignature,
			&value.SigningKeyID, &value.SignatureAlgorithm, &value.Compression, &value.MediaType,
			&value.Encryption, &value.RecipientKeyID, &value.SigningPublicKey, &value.RecipientPublicKeySHA256); err != nil {
			clearDeploymentFacts(result)
			return nil, errUnavailable
		}
		result = append(result, value)
	}
	if rows.Err() != nil {
		clearDeploymentFacts(result)
		return nil, errUnavailable
	}
	var deploymentCount, artifactCount, bindingCount int
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$1),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=$2),
		(SELECT count(*) FROM node_deployment_artifacts binding
		 JOIN node_deployments deployment ON deployment.id=binding.deployment_id
		  AND deployment.attempt=binding.deployment_attempt WHERE deployment.rollout_id=$1)`,
		rollout.ID, rollout.ConfigID).Scan(&deploymentCount, &artifactCount, &bindingCount)
	if err != nil {
		clearDeploymentFacts(result)
		return nil, errUnavailable
	}
	if len(result) == 0 || deploymentCount != len(result) || artifactCount != len(result) || bindingCount != len(result) {
		clearDeploymentFacts(result)
		return nil, errInvalidResponse
	}
	return result, nil
}

func validateDeploymentFacts(rollout rolloutFacts, deployments []deploymentFacts) ([32]byte, [32]byte, error) {
	type artifactBinding struct {
		NodeID, DeploymentID, EventID, ArtifactID, ArtifactSHA256, RecipientKeyID string
	}
	type recipientBinding struct {
		NodeID, RecipientKeyID, PublicKeySHA256 string
	}
	artifacts := make([]artifactBinding, len(deployments))
	recipients := make([]recipientBinding, len(deployments))
	seenNodes, seenDeployments, seenArtifacts := map[uuid.UUID]struct{}{}, map[uuid.UUID]struct{}{}, map[uuid.UUID]struct{}{}
	for index, deployment := range deployments {
		if deployment.DeploymentID == uuid.Nil || deployment.NodeID == uuid.Nil || deployment.EventID == uuid.Nil || deployment.ArtifactID == uuid.Nil ||
			deployment.ArtifactSize < 1 || int64(len(deployment.ArtifactWire)) != deployment.ArtifactSize ||
			deployment.SignatureAlgorithm != "ed25519" || deployment.Compression != "none" ||
			deployment.MediaType != edgepublish.OriginAuthArtifactMediaType ||
			deployment.Encryption != "hpke_x25519_hkdf_sha256_aes_256_gcm" || deployment.RecipientKeyID == "" ||
			len(deployment.SigningPublicKey) != ed25519.PublicKeySize || len(deployment.ArtifactSignature) != ed25519.SignatureSize ||
			len(deployment.RecipientPublicKeySHA256) != sha256.Size {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		if _, duplicate := seenNodes[deployment.NodeID]; duplicate {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		if _, duplicate := seenDeployments[deployment.DeploymentID]; duplicate {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		if _, duplicate := seenArtifacts[deployment.ArtifactID]; duplicate {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		seenNodes[deployment.NodeID], seenDeployments[deployment.DeploymentID], seenArtifacts[deployment.ArtifactID] = struct{}{}, struct{}{}, struct{}{}
		artifactDigest := sha256.Sum256(deployment.ArtifactWire)
		if !equalDigest(deployment.ArtifactSHA256, artifactDigest) ||
			!ed25519.Verify(ed25519.PublicKey(deployment.SigningPublicKey), deployment.ArtifactWire, deployment.ArtifactSignature) {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		var command agentv1.DeploymentCommand
		if proto.Unmarshal(deployment.CommandBytes, &command) != nil || command.GetEvent() == nil ||
			command.GetEvent().GetEventId() != deployment.EventID.String() || command.GetEvent().GetRequestId() != rollout.RequestID.String() ||
			command.GetEvent().GetCorrelationId() != rollout.CorrelationID.String() || command.GetEvent().GetTraceparent() != rollout.Traceparent ||
			command.GetDeploymentId() != deployment.DeploymentID.String() || command.GetRolloutId() != rollout.ID.String() ||
			command.GetConfigVersionId() != rollout.ConfigID.String() || command.GetAttempt() != 1 ||
			command.GetAction() != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(command.GetArtifacts()) != 1 ||
			command.GetHealthCheck() == nil || command.GetDeadlineTime() == nil || !command.GetDeadlineTime().AsTime().Equal(rollout.Deadline) ||
			command.GetHealthCheck().GetActivationTimeoutDuration() == nil ||
			command.GetHealthCheck().GetActivationTimeoutDuration().AsDuration() != time.Duration(rollout.ActivationTimeoutMS)*time.Millisecond ||
			command.GetHealthCheck().GetObservationWindowDuration() == nil ||
			command.GetHealthCheck().GetObservationWindowDuration().AsDuration() != time.Duration(rollout.ObservationWindowMS)*time.Millisecond ||
			command.GetHealthCheck().GetRequiredConsecutiveSuccesses() != rollout.RequiredSuccesses || !equalStringPointer(command.GetEvent().TaskId, rollout.TaskID) {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		descriptor := command.GetArtifacts()[0]
		if descriptor.GetArtifactId() != deployment.ArtifactID.String() ||
			descriptor.GetKind() != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
			descriptor.GetSizeBytes() != uint64(deployment.ArtifactSize) || !bytes.Equal(descriptor.GetSha256(), deployment.ArtifactSHA256) ||
			!bytes.Equal(descriptor.GetSignature(), deployment.ArtifactSignature) || descriptor.GetSigningKeyId() != deployment.SigningKeyID ||
			descriptor.GetSignatureAlgorithm() != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
			descriptor.GetCompression() != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
			descriptor.GetMediaType() != edgepublish.OriginAuthArtifactMediaType ||
			descriptor.GetEncryptionAlgorithm() != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
			descriptor.RecipientKeyId == nil || descriptor.GetRecipientKeyId() != deployment.RecipientKeyID {
			return [32]byte{}, [32]byte{}, errInvalidResponse
		}
		artifacts[index] = artifactBinding{deployment.NodeID.String(), deployment.DeploymentID.String(), deployment.EventID.String(),
			deployment.ArtifactID.String(), hexDigest(artifactDigest), deployment.RecipientKeyID}
		recipients[index] = recipientBinding{deployment.NodeID.String(), deployment.RecipientKeyID,
			hex.EncodeToString(deployment.RecipientPublicKeySHA256)}
	}
	artifactJSON, artifactErr := json.Marshal(artifacts)
	recipientJSON, recipientErr := json.Marshal(recipients)
	if artifactErr != nil || recipientErr != nil {
		return [32]byte{}, [32]byte{}, errInvalidResponse
	}
	return sha256.Sum256(artifactJSON), sha256.Sum256(recipientJSON), nil
}

type runtimeSessionAuthenticator struct{ service *identity.Service }

func (authenticator *runtimeSessionAuthenticator) Authenticate(ctx context.Context, rawToken string) (identity.AuthenticatedSession, error) {
	if authenticator == nil || authenticator.service == nil || ctx == nil {
		return identity.AuthenticatedSession{}, edgedeployment.ErrUnauthenticated
	}
	session, err := authenticator.service.AuthenticateSession(ctx, rawToken)
	if errors.Is(err, identity.ErrInvalidSession) {
		return identity.AuthenticatedSession{}, edgedeployment.ErrUnauthenticated
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
		return uuid.Nil, edgedeployment.ErrPermissionDenied
	}
	if principal.ScopeKind == edgedeployment.ScopeKindTenant && principal.ScopeID != scopeID {
		return uuid.Nil, edgedeployment.ErrPermissionDenied
	}
	var tenantID uuid.UUID
	var active bool
	err := resolver.pool.QueryRow(ctx, `SELECT scope.tenant_id,tenant.status='active'
		FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.id=$1 AND scope.kind='tenant'`, scopeID).Scan(&tenantID, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		if principal.ScopeKind == edgedeployment.ScopeKindTenant {
			return uuid.Nil, edgedeployment.ErrPermissionDenied
		}
		return uuid.Nil, edgedeployment.ErrNotFound
	}
	if err != nil {
		if ctx.Err() != nil {
			return uuid.Nil, ctx.Err()
		}
		return uuid.Nil, errUnavailable
	}
	if !active || tenantID == uuid.Nil || principal.ScopeKind == edgedeployment.ScopeKindTenant &&
		(principal.TenantID == nil || *principal.TenantID != tenantID) {
		return uuid.Nil, edgedeployment.ErrPermissionDenied
	}
	return tenantID, nil
}

func stablePublishError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, stable := range []error{
		errInvalidRequest, errInvalidResponse, edgedeployment.ErrInvalidInput, edgedeployment.ErrUnauthenticated,
		edgedeployment.ErrPermissionDenied, edgedeployment.ErrNotFound, edgedeployment.ErrIdempotencyConflict,
		edgedeployment.ErrNodeNotFound, edgedeployment.ErrConfigurationScopeConflict, edgedeployment.ErrNodeDeploymentActive,
		edgedeployment.ErrNodeReconciliationRequired, edgedeployment.ErrNodeRecipientKeyUnavailable,
		edgedeployment.ErrSecretArtifactContract, originauthcontrol.ErrInvalidInput, originauthcontrol.ErrValidation,
		originauthcontrol.ErrPermissionDenied, originauthcontrol.ErrUnauthenticated, originauthcontrol.ErrNotFound,
		originauthcontrol.ErrRevisionConflict, originauthcontrol.ErrCredentialUnverified, originauthcontrol.ErrEncryptionUnavailable,
		edgepublish.ErrInvalidInput, edgepublish.ErrOriginAuthArtifact,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return errOutcomeUnknown
}

func mapAuthorizationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return edgedeployment.ErrUnauthenticated
	}
	if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidInput) {
		return edgedeployment.ErrPermissionDenied
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
	case errors.Is(err, edgedeployment.ErrUnauthenticated), errors.Is(err, originauthcontrol.ErrUnauthenticated),
		errors.Is(err, identity.ErrInvalidSession):
		return http.StatusUnauthorized, "origin_auth_edge_publication_unauthenticated", "需要重新登录"
	case errors.Is(err, edgedeployment.ErrPermissionDenied), errors.Is(err, originauthcontrol.ErrPermissionDenied):
		return http.StatusForbidden, "origin_auth_edge_publication_permission_denied", "没有此发布操作的权限"
	case errors.Is(err, errInvalidRequest), errors.Is(err, edgedeployment.ErrInvalidInput), errors.Is(err, originauthcontrol.ErrInvalidInput):
		return http.StatusBadRequest, "origin_auth_edge_publication_invalid_request", "请求参数无效"
	case errors.Is(err, edgedeployment.ErrNotFound), errors.Is(err, originauthcontrol.ErrNotFound):
		return http.StatusNotFound, "origin_auth_edge_publication_not_found", "未找到源配置或发布记录"
	case errors.Is(err, edgedeployment.ErrIdempotencyConflict):
		return http.StatusConflict, "origin_auth_edge_publication_idempotency_conflict", "幂等键已绑定其他请求"
	case errors.Is(err, originauthcontrol.ErrRevisionConflict):
		return http.StatusPreconditionFailed, "origin_auth_edge_publication_revision_conflict", "源配置版本已变化"
	case errors.Is(err, edgedeployment.ErrNodeNotFound), errors.Is(err, edgedeployment.ErrConfigurationScopeConflict),
		errors.Is(err, edgedeployment.ErrNodeDeploymentActive), errors.Is(err, edgedeployment.ErrNodeReconciliationRequired),
		errors.Is(err, edgedeployment.ErrNodeRecipientKeyUnavailable):
		return http.StatusUnprocessableEntity, "origin_auth_edge_publication_target_ineligible", "目标节点或其接收密钥当前不可发布"
	case errors.Is(err, originauthcontrol.ErrValidation), errors.Is(err, originauthcontrol.ErrCredentialUnverified):
		return http.StatusUnprocessableEntity, "origin_auth_edge_publication_source_ineligible", "源站鉴权配置当前不可发布"
	case errors.Is(err, errInvalidResponse), errors.Is(err, edgedeployment.ErrSecretArtifactContract),
		errors.Is(err, edgepublish.ErrOriginAuthArtifact):
		return http.StatusBadGateway, "origin_auth_edge_publication_invalid_response", "发布结果身份校验失败"
	case errors.Is(err, errOutcomeUnknown):
		return http.StatusServiceUnavailable, "origin_auth_edge_publication_outcome_unknown", "发布结果未知，请按提示原样重试"
	case errors.Is(err, errMethod):
		return http.StatusMethodNotAllowed, "origin_auth_edge_publication_method_not_allowed", "请求方法不受支持"
	default:
		return http.StatusServiceUnavailable, "origin_auth_edge_publication_unavailable", "源站鉴权发布服务暂不可用"
	}
}

func strictUUID(raw string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed == uuid.Nil || parsed.String() != raw {
		return uuid.Nil, errInvalidRequest
	}
	return parsed, nil
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
	if principal.ScopeKind == edgedeployment.ScopeKindPlatform {
		return principal.TenantID == nil
	}
	return principal.ScopeKind == edgedeployment.ScopeKindTenant && principal.TenantID != nil && *principal.TenantID != uuid.Nil
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

func equalStringPointer(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalDigest(raw []byte, digest [sha256.Size]byte) bool {
	return len(raw) == sha256.Size && bytes.Equal(raw, digest[:]) && digest != ([sha256.Size]byte{})
}

func clearProductionMaterial(material *originauthcontrol.ProductionMaterial) {
	if material == nil {
		return
	}
	clearBytes(material.CanonicalSnapshot)
	for index := range material.Credentials {
		material.Credentials[index].Secret.AccessKeyID = ""
		material.Credentials[index].Secret.SecretAccessKey = ""
		material.Credentials[index].Secret.SessionToken = ""
	}
}

func clearDeploymentFacts(values []deploymentFacts) {
	for index := range values {
		clearBytes(values[index].ArtifactWire)
		values[index].ArtifactWire = nil
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func digestETag(digest [sha256.Size]byte) string { return `"sha256-` + hexDigest(digest) + `"` }
func hexDigest(digest [sha256.Size]byte) string  { return hex.EncodeToString(digest[:]) }

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

var _ publicationPublisher = (*runtimePublicationPublisher)(nil)
var _ publicationReader = (*runtimePublicationReader)(nil)
var _ sessionAuthenticator = (*runtimeSessionAuthenticator)(nil)
var _ tenantScopeResolver = (*runtimeTenantScopeResolver)(nil)
var _ edgepublish.OriginAuthProductionSource = (*revisionBoundSource)(nil)
