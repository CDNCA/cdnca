package dnscredentialrewraphttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultMaxRequestBytes int64 = 64 << 10
	defaultQueryTimeout          = 5 * time.Second
	defaultCommandTimeout        = 5 * time.Minute
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Config struct {
	MaxRequestBytes int64
	QueryTimeout    time.Duration
	CommandTimeout  time.Duration
}

type Handler struct {
	authorizer      Authorizer
	domain          Domain
	maxRequestBytes int64
	queryTimeout    time.Duration
	commandTimeout  time.Duration
}

func NewHandler(dependencies Dependencies, config Config) (*Handler, error) {
	if dependencies.Authorizer == nil || dependencies.Domain == nil {
		return nil, ErrInvalidConfig
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaultCommandTimeout
	}
	if config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 ||
		config.QueryTimeout <= 0 || config.QueryTimeout > 30*time.Second ||
		config.CommandTimeout <= 0 || config.CommandTimeout > 15*time.Minute {
		return nil, ErrInvalidConfig
	}
	return &Handler{
		authorizer: dependencies.Authorizer, domain: dependencies.Domain,
		maxRequestBytes: config.MaxRequestBytes, queryTimeout: config.QueryTimeout,
		commandTimeout: config.CommandTimeout,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	requestID, requestIDValid := requestIdentifier(request)
	writer.Header().Set("X-Request-ID", requestID)
	jobID, collection, found := resolveRoute(request.URL.Path)
	if !found {
		handler.writeError(writer, http.StatusNotFound, CodeJobNotFound, requestID)
		return
	}
	wantedMethod := http.MethodGet
	if collection {
		wantedMethod = http.MethodPost
	}
	if request.Method != wantedMethod {
		writer.Header().Set("Allow", wantedMethod)
		handler.writeError(writer, http.StatusMethodNotAllowed, CodeMethodNotAllowed, requestID)
		return
	}
	if !requestIDValid || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
		return
	}
	rawSession, ok := bearerSession(request)
	if !ok || hasForbiddenCredentialHeaders(request.Header) {
		handler.writeError(writer, http.StatusUnauthorized, CodeAuthenticationRequired, requestID)
		return
	}
	timeout := handler.queryTimeout
	if collection {
		timeout = handler.commandTimeout
	}
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	owner, err := handler.authorizer.Authorize(ctx, rawSession)
	if err != nil || !owner.valid() {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	if collection {
		handler.submit(writer, request.WithContext(ctx), requestID, owner)
		return
	}
	if !emptyRequestBody(request) {
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
		return
	}
	job, err := handler.domain.Get(ctx, GetRequest{Owner: owner, JobID: jobID})
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	handler.writeJob(writer, job, requestID)
}

func (handler *Handler) submit(writer http.ResponseWriter, request *http.Request, requestID string, owner Owner) {
	key, ok := singleHeader(request.Header, "Idempotency-Key")
	if !ok || !metadataPattern.MatchString(key) {
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
		return
	}
	contentType, ok := singleHeader(request.Header, "Content-Type")
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if !ok || err != nil || mediaType != "application/json" || len(parameters) != 0 {
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
		return
	}
	var body struct {
		Items []struct {
			ProviderID       string `json:"provider_id"`
			ExpectedRevision int64  `json:"expected_revision"`
		} `json:"items"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureEOF(decoder) != nil || len(body.Items) == 0 || len(body.Items) > MaxBatchItems {
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
		return
	}
	items := make([]BatchItem, len(body.Items))
	providers := make(map[uuid.UUID]struct{}, len(items))
	for index, input := range body.Items {
		providerID, parseErr := uuid.Parse(input.ProviderID)
		if parseErr != nil || providerID == uuid.Nil || providerID.String() != input.ProviderID || input.ExpectedRevision < 1 {
			handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
			return
		}
		if _, duplicate := providers[providerID]; duplicate {
			handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
			return
		}
		providers[providerID] = struct{}{}
		items[index] = BatchItem{ProviderID: providerID, ExpectedRevision: input.ExpectedRevision}
	}
	job, replayed, err := handler.domain.Submit(request.Context(), SubmitRequest{
		Owner: owner, IdempotencyKey: key, RequestID: requestID, Items: items,
	})
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	if replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	handler.writeJob(writer, job, requestID)
}

func (handler *Handler) writeJob(writer http.ResponseWriter, job Job, requestID string) {
	if !validJob(job) {
		handler.writeError(writer, http.StatusServiceUnavailable, CodeUnavailable, requestID)
		return
	}
	if job.Items == nil {
		job.Items = []ItemProgress{}
	}
	writer.Header().Set("Location", CollectionRoute+"/"+job.ID.String())
	if job.State == JobProcessing {
		writer.Header().Set("Retry-After", "1")
	}
	writeJSON(writer, http.StatusAccepted, jobEnvelope{Job: job})
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrUnauthenticated), err == nil:
		handler.writeError(writer, http.StatusUnauthorized, CodeAuthenticationRequired, requestID)
	case errors.Is(err, ErrPermissionDenied):
		handler.writeError(writer, http.StatusForbidden, CodePermissionDenied, requestID)
	case errors.Is(err, ErrInvalidRequest):
		handler.writeError(writer, http.StatusBadRequest, CodeInvalidRequest, requestID)
	case errors.Is(err, ErrJobNotFound):
		handler.writeError(writer, http.StatusNotFound, CodeJobNotFound, requestID)
	case errors.Is(err, ErrIdempotencyConflict):
		handler.writeError(writer, http.StatusConflict, CodeIdempotencyConflict, requestID)
	default:
		handler.writeError(writer, http.StatusServiceUnavailable, CodeUnavailable, requestID)
	}
}

func (*Handler) writeError(writer http.ResponseWriter, status int, code, requestID string) {
	writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID}})
}

func resolveRoute(path string) (uuid.UUID, bool, bool) {
	if path == CollectionRoute {
		return uuid.Nil, true, true
	}
	prefix := CollectionRoute + "/"
	if !strings.HasPrefix(path, prefix) || strings.Contains(strings.TrimPrefix(path, prefix), "/") {
		return uuid.Nil, false, false
	}
	raw := strings.TrimPrefix(path, prefix)
	id, err := uuid.Parse(raw)
	return id, false, err == nil && id != uuid.Nil && id.String() == raw
}

func requestIdentifier(request *http.Request) (string, bool) {
	value, ok := singleHeader(request.Header, "X-Request-ID")
	if ok && metadataPattern.MatchString(value) {
		return value, true
	}
	return uuid.NewString(), false
}

func bearerSession(request *http.Request) (string, bool) {
	value, ok := singleHeader(request.Header, "Authorization")
	if !ok {
		return "", false
	}
	scheme, raw, found := strings.Cut(value, " ")
	return raw, found && strings.EqualFold(scheme, "Bearer") && len(raw) >= 1 && len(raw) <= 8192 &&
		strings.TrimSpace(raw) == raw && !strings.ContainsAny(raw, " \t\r\n,")
}

func hasForbiddenCredentialHeaders(header http.Header) bool {
	for _, name := range []string{
		"X-API-Key", "X-Workload-Identity", "X-Actor-User-ID", "X-Actor-Scope-ID",
		"X-Session-ID", "X-Tenant-ID", "X-Principal-ID", "X-Principal-Scope",
	} {
		if len(header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], "\r\n") {
		return "", false
	}
	return values[0], true
}

func emptyRequestBody(request *http.Request) bool {
	return request.ContentLength == 0 && len(request.TransferEncoding) == 0 &&
		(request.Body == nil || request.Body == http.NoBody)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrInvalidRequest
}

func validJob(job Job) bool {
	if job.ID == uuid.Nil || job.CreatedAt.IsZero() || job.UpdatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) ||
		job.Requested < 0 || job.Completed < 0 ||
		job.Succeeded < 0 || job.Replayed < 0 || job.Conflicted < 0 || job.Failed < 0 ||
		job.Completed > job.Requested || len(job.Items) != job.Requested {
		return false
	}
	if job.State != JobProcessing && job.State != JobCompleted && job.State != JobCompletedWithErrors {
		return false
	}
	for _, item := range job.Items {
		if item.ProviderID == uuid.Nil || item.ExpectedRevision < 1 ||
			item.Status != ItemPending && item.Status != ItemCompleted && item.Status != ItemReplayed &&
				item.Status != ItemConflict && item.Status != ItemFailed {
			return false
		}
	}
	return true
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
