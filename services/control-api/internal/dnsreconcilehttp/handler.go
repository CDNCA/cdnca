package dnsreconcilehttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/google/uuid"
)

var (
	metadataPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idempotencyPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	providerIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	providerCodePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	traceparentPattern  = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$`)
)

type Handler struct {
	dependencies    Dependencies
	maxRequestBytes int64
	queryTimeout    time.Duration
	commandTimeout  time.Duration
}

type routeKind uint8

const (
	routeDryRun routeKind = iota + 1
	routeApply
	routeGet
	routeCommit
	routeCancel
	routeProviderReport
)

type route struct {
	kind   routeKind
	siteID uuid.UUID
	taskID uuid.UUID
}

type requestIDContextKey struct{}

type partitionedHandler struct {
	handler  *Handler
	provider bool
}

// NewHandler accepts an assembled domain for focused tests and package-level
// adapters. Production wiring must use NewProductionHandler.
func NewHandler(dependencies Dependencies, config Config) (*Handler, error) {
	if isNil(dependencies.Sessions) || isNil(dependencies.IAM) ||
		isNil(dependencies.Domain) || isNil(dependencies.Workloads) {
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
		config.QueryTimeout <= 0 || config.QueryTimeout > time.Minute ||
		config.CommandTimeout <= 0 || config.CommandTimeout > time.Hour {
		return nil, ErrInvalidConfig
	}
	return &Handler{dependencies: dependencies, maxRequestBytes: config.MaxRequestBytes,
		queryTimeout: config.QueryTimeout, commandTimeout: config.CommandTimeout}, nil
}

// NewTenantHandler exposes only the five session-authenticated tenant routes.
func NewTenantHandler(handler *Handler) http.Handler {
	return &partitionedHandler{handler: handler}
}

// NewProviderReportHandler exposes only the workload-authenticated report route.
func NewProviderReportHandler(handler *Handler) http.Handler {
	return &partitionedHandler{handler: handler, provider: true}
}

func (partition *partitionedHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if partition == nil || partition.handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	resolved, ok := resolveRoute(request.URL.Path)
	if !ok || (resolved.kind == routeProviderReport) != partition.provider {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		partition.handler.writeAPIError(writer, request, http.StatusNotFound,
			"dns_reconcile_route_not_found", "DNS reconciliation route was not found")
		return
	}
	partition.handler.ServeHTTP(writer, request)
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, valid := requestIdentifier(request)
	writer.Header().Set("X-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDContextKey{}, requestID))
	if handler == nil || isNil(handler.dependencies.Domain) || !valid {
		handler.writeError(writer, request, ErrInvalidRequest, false)
		return
	}
	if request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Opaque != "" || request.URL.Fragment != "" {
		handler.writeError(writer, request, ErrInvalidRequest, false)
		return
	}
	resolved, ok := resolveRoute(request.URL.Path)
	if !ok {
		handler.writeAPIError(writer, request, http.StatusNotFound, "dns_reconcile_route_not_found", "DNS reconciliation route was not found")
		return
	}
	wantMethod := http.MethodPost
	if resolved.kind == routeGet {
		wantMethod = http.MethodGet
	}
	if request.Method != wantMethod {
		writer.Header().Set("Allow", wantMethod)
		handler.writeAPIError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
		return
	}
	timeout := handler.commandTimeout
	if resolved.kind == routeGet || resolved.kind == routeDryRun {
		timeout = handler.queryTimeout
	}
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	request = request.WithContext(ctx)
	if resolved.kind == routeProviderReport {
		handler.handleProviderReport(writer, request, resolved)
		return
	}
	handler.handleTenant(writer, request, resolved)
}

func (handler *Handler) handleTenant(writer http.ResponseWriter, request *http.Request, route route) {
	principal, err := handler.authenticateSession(request)
	if err != nil {
		handler.writeError(writer, request, err, false)
		return
	}
	permission := PermissionRead
	mutation := false
	if route.kind == routeApply || route.kind == routeCommit || route.kind == routeCancel {
		permission = PermissionManage
		mutation = true
	}
	if err := handler.dependencies.IAM.Authorize(request.Context(), AuthorizationRequest{
		Principal: principal, TenantID: principal.TenantID, SiteID: route.siteID, Permission: permission,
	}); err != nil {
		handler.writeError(writer, request, mapIAMError(err), mutation)
		return
	}
	switch route.kind {
	case routeDryRun:
		if _, err := bodyMetadata(request); err != nil {
			handler.writeError(writer, request, err, false)
			return
		}
		check, err := handler.decodeCheck(writer, request, principal.TenantID, route.siteID)
		if err != nil {
			handler.writeError(writer, request, err, false)
			return
		}
		result, err := handler.dependencies.Domain.DryRun(request.Context(), dnsreconcile.DryRunRequest{
			TenantID: principal.TenantID, SiteID: route.siteID, ActorUserID: principal.SubjectID,
			RequestID: request.Context().Value(requestIDContextKey{}).(string), Check: check,
		})
		if err == nil && !reconcileResultMatchesScope(result, principal.TenantID, route.siteID) {
			err = ErrUnavailable
		}
		if err != nil {
			handler.writeError(writer, request, err, false)
			return
		}
		handler.writeJSON(writer, http.StatusOK, reconcileResultViewOf(result))
	case routeApply:
		metadata, err := parseMutationMetadata(request)
		if err != nil {
			handler.writeError(writer, request, err, true)
			return
		}
		check, err := handler.decodeCheck(writer, request, principal.TenantID, route.siteID)
		if err != nil {
			handler.writeError(writer, request, err, true)
			return
		}
		task, err := handler.dependencies.Domain.Apply(request.Context(), dnsreconcile.ApplyRequest{
			TenantID: principal.TenantID, SiteID: route.siteID, ActorUserID: principal.SubjectID,
			IdempotencyKey: metadata.IdempotencyKey,
			RequestID:      metadata.RequestID, Traceparent: metadata.Traceparent,
			ExpectedRevision: metadata.ExpectedRevision, Check: check,
		})
		if err == nil && !taskMatches(task, principal.TenantID, route.siteID, uuid.Nil) {
			err = ErrUnavailable
		}
		handler.writeTask(writer, request, http.StatusAccepted, task, err, true)
	case routeGet:
		if err := validateOptionalTraceparent(request); err != nil {
			handler.writeError(writer, request, err, false)
			return
		}
		task, err := handler.dependencies.Domain.Get(request.Context(), principal.TenantID, route.taskID)
		if err == nil && !taskMatches(task, principal.TenantID, route.siteID, route.taskID) {
			err = dnsreconcile.ErrNotFound
		}
		handler.writeTask(writer, request, http.StatusOK, task, err, false)
	case routeCommit, routeCancel:
		metadata, err := parseMutationMetadata(request)
		if err == nil {
			err = handler.decodeJSON(writer, request, &emptyBody{})
		}
		if err != nil {
			handler.writeError(writer, request, err, true)
			return
		}
		if route.kind == routeCommit {
			task, commandErr := handler.dependencies.Domain.Commit(request.Context(), dnsreconcile.CommitRequest{
				TenantID: principal.TenantID, SiteID: route.siteID, TaskID: route.taskID,
				ActorUserID:    principal.SubjectID,
				IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
				Traceparent: metadata.Traceparent, ExpectedRevision: metadata.ExpectedRevision,
			})
			if commandErr == nil && !taskMatches(task, principal.TenantID, route.siteID, route.taskID) {
				commandErr = ErrUnavailable
			}
			handler.writeTask(writer, request, http.StatusOK, task, commandErr, true)
			return
		}
		task, commandErr := handler.dependencies.Domain.Cancel(request.Context(), dnsreconcile.CancelRequest{
			TenantID: principal.TenantID, SiteID: route.siteID, TaskID: route.taskID,
			ActorUserID:    principal.SubjectID,
			IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
			Traceparent: metadata.Traceparent, ExpectedRevision: metadata.ExpectedRevision,
		})
		if commandErr == nil && !taskMatches(task, principal.TenantID, route.siteID, route.taskID) {
			commandErr = ErrUnavailable
		}
		handler.writeTask(writer, request, http.StatusOK, task, commandErr, true)
	}
}

func (handler *Handler) handleProviderReport(writer http.ResponseWriter, request *http.Request, route route) {
	if len(request.Header.Values("Authorization")) != 0 {
		handler.writeError(writer, request, ErrWorkloadUnauthenticated, true)
		return
	}
	principal, err := handler.dependencies.Workloads.Authenticate(request)
	if err != nil || !principal.valid() {
		if err != nil && !errors.Is(err, ErrWorkloadUnauthenticated) {
			err = ErrUnavailable
		} else {
			err = ErrWorkloadUnauthenticated
		}
		handler.writeError(writer, request, err, true)
		return
	}
	metadata, err := parseMutationMetadata(request)
	if err != nil {
		handler.writeError(writer, request, err, true)
		return
	}
	var body providerReportBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeError(writer, request, err, true)
		return
	}
	if !validProviderReport(body) {
		handler.writeError(writer, request, ErrInvalidRequest, true)
		return
	}
	providerRequestID, providerRecordID, providerRevision := "", "", int64(0)
	if body.ProviderRequestID != nil {
		providerRequestID = *body.ProviderRequestID
	}
	if body.ProviderRecordID != nil {
		providerRecordID = *body.ProviderRecordID
	}
	if body.ProviderRevision != nil {
		providerRevision = *body.ProviderRevision
	}
	result, err := handler.dependencies.Domain.RecordProviderReport(request.Context(), dnsreconcile.ProviderReportRequest{
		TenantID: principal.TenantID, SiteID: principal.SiteID, TaskID: route.taskID,
		WorkloadID: principal.WorkloadID, JobAttempt: body.JobAttempt, LeaseID: body.LeaseID,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		Traceparent: metadata.Traceparent, ExpectedRevision: metadata.ExpectedRevision,
		Report: dnscheck.ProviderReport{
			ClientRequestID: body.ClientRequestID, ProviderRequestID: providerRequestID,
			ProviderRecordID: providerRecordID, ProviderRevision: providerRevision,
			Status: body.Status, ErrorClass: body.ErrorClass, ErrorCode: body.ErrorCode,
			RetryAfter: time.Duration(body.RetryAfterSeconds) * time.Second, Sequence: body.Sequence,
		},
	})
	if err == nil {
		if !taskMatches(result.Task, principal.TenantID, principal.SiteID, route.taskID) {
			err = ErrUnavailable
		}
	}
	if err == nil {
		writer.Header().Set("X-Report-Accepted", strconv.FormatBool(result.Accepted))
	}
	handler.writeTask(writer, request, http.StatusOK, result.Task, err, true)
}

func validProviderReport(body providerReportBody) bool {
	if !metadataPattern.MatchString(body.ClientRequestID) || body.JobAttempt == 0 || body.LeaseID == uuid.Nil || body.Sequence == 0 ||
		!validOptionalProviderID(body.ProviderRequestID) || !validOptionalProviderID(body.ProviderRecordID) ||
		(body.ProviderRevision != nil && *body.ProviderRevision <= 0) {
		return false
	}
	hasProviderIdentity := body.ProviderRecordID != nil || body.ProviderRevision != nil
	switch body.Status {
	case dnscheck.OperationRunning:
		return body.ProviderRequestID == nil && !hasProviderIdentity && body.RetryAfterSeconds == 0 &&
			body.ErrorClass == dnscheck.ProviderErrorNone && body.ErrorCode == ""
	case dnscheck.OperationSucceeded:
		return body.ProviderRequestID != nil && body.ProviderRecordID != nil && body.ProviderRevision != nil &&
			body.RetryAfterSeconds == 0 && body.ErrorClass == dnscheck.ProviderErrorNone && body.ErrorCode == ""
	case dnscheck.OperationTransientFailed:
		return !hasProviderIdentity && body.RetryAfterSeconds >= 0 && body.RetryAfterSeconds <= 3600 &&
			(body.ErrorClass == dnscheck.ProviderErrorTransient || body.ErrorClass == dnscheck.ProviderErrorTimeout) &&
			providerCodePattern.MatchString(body.ErrorCode)
	case dnscheck.OperationPermanentFailed:
		return !hasProviderIdentity && body.RetryAfterSeconds == 0 && body.ErrorClass == dnscheck.ProviderErrorPermanent &&
			providerCodePattern.MatchString(body.ErrorCode)
	case dnscheck.OperationRevisionConflict:
		return !hasProviderIdentity && body.RetryAfterSeconds == 0 && body.ErrorClass == dnscheck.ProviderErrorRevisionConflict &&
			providerCodePattern.MatchString(body.ErrorCode)
	case dnscheck.OperationCancelled:
		return !hasProviderIdentity && body.RetryAfterSeconds == 0 && body.ErrorClass == dnscheck.ProviderErrorCancelled &&
			providerCodePattern.MatchString(body.ErrorCode)
	default:
		return false
	}
}

func validOptionalProviderID(value *string) bool {
	return value == nil || validProviderID(*value)
}

func validProviderID(value string) bool {
	return len(value) >= 1 && len(value) <= 256 && providerIDPattern.MatchString(value)
}

func taskMatches(task dnsreconcile.Task, tenantID, siteID, taskID uuid.UUID) bool {
	if task.ID == uuid.Nil || task.TenantID != tenantID || task.SiteID != siteID ||
		(taskID != uuid.Nil && task.ID != taskID) {
		return false
	}
	request := task.Prepared.Request
	if !reflect.DeepEqual(request, dnscheck.CheckRequest{}) &&
		(request.TenantID != tenantID || request.SiteID != siteID ||
			request.Provider.TenantID != tenantID || request.Provider.SiteID != siteID) {
		return false
	}
	return reconcileResultMatchesScope(task.Result, tenantID, siteID)
}

func reconcileResultMatchesScope(result dnscheck.ReconcileResult, tenantID, siteID uuid.UUID) bool {
	if result.TenantID != tenantID || result.SiteID != siteID {
		return false
	}
	if !reflect.DeepEqual(result.Plan, dnscheck.RepairPlan{}) &&
		(result.Plan.TenantID != tenantID || result.Plan.SiteID != siteID) {
		return false
	}
	if result.LastCheck == nil {
		return true
	}
	if result.LastCheck.TenantID != tenantID || result.LastCheck.SiteID != siteID {
		return false
	}
	return reflect.DeepEqual(result.LastCheck.RepairPlan, dnscheck.RepairPlan{}) ||
		(result.LastCheck.RepairPlan.TenantID == tenantID && result.LastCheck.RepairPlan.SiteID == siteID)
}

func (handler *Handler) authenticateSession(request *http.Request) (Principal, error) {
	value, err := singleHeader(request, "Authorization", true)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	scheme, rawSession, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || rawSession == "" || len(rawSession) > 8192 ||
		strings.TrimSpace(rawSession) != rawSession || strings.ContainsAny(rawSession, " \t\r\n,") {
		return Principal{}, ErrUnauthenticated
	}
	principal, err := handler.dependencies.Sessions.AuthenticateSession(request.Context(), rawSession)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, ErrUnavailable
	}
	if !principal.valid() {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

func resolveRoute(path string) (route, bool) {
	parts := strings.Split(path, "/")
	if len(parts) >= 6 && parts[0] == "" && parts[1] == "v1" && parts[2] == "sites" && parts[4] == "dns-reconcile" {
		siteID, err := strictUUID(parts[3])
		if err != nil {
			return route{}, false
		}
		switch {
		case len(parts) == 6 && parts[5] == "dry-run":
			return route{kind: routeDryRun, siteID: siteID}, true
		case len(parts) == 6 && parts[5] == "apply":
			return route{kind: routeApply, siteID: siteID}, true
		case len(parts) == 7 && parts[5] == "tasks":
			taskID, err := strictUUID(parts[6])
			return route{kind: routeGet, siteID: siteID, taskID: taskID}, err == nil
		case len(parts) == 8 && parts[5] == "tasks" && (parts[7] == "commit" || parts[7] == "cancel"):
			taskID, err := strictUUID(parts[6])
			kind := routeCommit
			if parts[7] == "cancel" {
				kind = routeCancel
			}
			return route{kind: kind, siteID: siteID, taskID: taskID}, err == nil
		}
	}
	if len(parts) == 8 && parts[0] == "" && parts[1] == "internal" && parts[2] == "v1" &&
		parts[3] == "dns" && parts[4] == "reconcile" && parts[5] == "tasks" && parts[7] == "provider-reports" {
		taskID, err := strictUUID(parts[6])
		return route{kind: routeProviderReport, taskID: taskID}, err == nil
	}
	return route{}, false
}

func (handler *Handler) decodeCheck(writer http.ResponseWriter, request *http.Request, tenantID, siteID uuid.UUID) (dnscheck.CheckRequest, error) {
	var body checkBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		return dnscheck.CheckRequest{}, err
	}
	zoneID, err := strictUUID(body.Provider.ZoneID)
	if err != nil || body.PropagationWindowSeconds <= 0 || body.PropagationWindowSeconds > int64((7*24*time.Hour)/time.Second) {
		return dnscheck.CheckRequest{}, ErrInvalidRequest
	}
	if !validLineWeight(body.Line, body.Weight) {
		return dnscheck.CheckRequest{}, ErrInvalidRequest
	}
	expected := make([]dnscheck.ExpectedRecord, len(body.Expected))
	for index, item := range body.Expected {
		recordType, typeErr := parseRecordType(item.Type)
		if typeErr != nil {
			return dnscheck.CheckRequest{}, typeErr
		}
		expected[index] = dnscheck.ExpectedRecord{Type: recordType, Values: append([]string(nil), item.Values...)}
	}
	records := make([]dnscheck.ProviderRecord, len(body.Provider.Records))
	for index, item := range body.Provider.Records {
		if !validProviderID(item.RecordID) || !validLineWeight(item.Line, item.Weight) {
			return dnscheck.CheckRequest{}, ErrInvalidRequest
		}
		recordType, typeErr := parseRecordType(item.Type)
		if typeErr != nil {
			return dnscheck.CheckRequest{}, typeErr
		}
		records[index] = dnscheck.ProviderRecord{RecordID: item.RecordID, Name: item.Name,
			Type: recordType, Value: item.Value, TTL: item.TTL, Line: item.Line, Weight: item.Weight}
	}
	return dnscheck.CheckRequest{
		TenantID: tenantID, SiteID: siteID, Name: body.Name, Expected: expected,
		AuthoritativeNS: append([]string(nil), body.AuthoritativeNS...), TTL: body.TTL,
		Line: body.Line, Weight: body.Weight,
		PropagationStartedAt: body.PropagationStartedAt,
		PropagationWindow:    time.Duration(body.PropagationWindowSeconds) * time.Second,
		Provider: dnscheck.ProviderSnapshot{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID,
			Revision: body.Provider.Revision, Records: records},
	}, nil
}

func validLineWeight(line string, weight uint32) bool {
	return weight <= 100 && len(line) <= 64 && line == strings.TrimSpace(line) && !strings.ContainsAny(line, "\r\n\x00")
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	contentType, err := singleHeader(request, "Content-Type", true)
	if err != nil {
		return ErrInvalidRequest
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func parseMutationMetadata(request *http.Request) (mutationMetadata, error) {
	key, keyErr := singleHeader(request, "Idempotency-Key", true)
	requestID, requestErr := singleHeader(request, "X-Request-ID", true)
	traceparent, traceErr := singleHeader(request, "traceparent", true)
	revision, revisionErr := parseRevision(request)
	if keyErr != nil || requestErr != nil || traceErr != nil || revisionErr != nil ||
		!idempotencyPattern.MatchString(key) || !metadataPattern.MatchString(requestID) || !validTraceparent(traceparent) {
		return mutationMetadata{}, ErrInvalidRequest
	}
	return mutationMetadata{IdempotencyKey: key, RequestID: requestID, Traceparent: traceparent,
		ExpectedRevision: revision}, nil
}

func bodyMetadata(request *http.Request) (string, error) {
	requestID, requestErr := singleHeader(request, "X-Request-ID", true)
	traceparent, traceErr := singleHeader(request, "traceparent", true)
	if requestErr != nil || traceErr != nil || !metadataPattern.MatchString(requestID) || !validTraceparent(traceparent) {
		return "", ErrInvalidRequest
	}
	return requestID, nil
}

func validateOptionalTraceparent(request *http.Request) error {
	value, err := singleHeader(request, "traceparent", false)
	if err != nil || value != "" && !validTraceparent(value) {
		return ErrInvalidRequest
	}
	return nil
}

func validTraceparent(value string) bool {
	match := traceparentPattern.FindStringSubmatch(value)
	return len(match) == 4 && match[1] != strings.Repeat("0", 32) && match[2] != strings.Repeat("0", 16)
}

func parseRevision(request *http.Request) (int64, error) {
	value, err := singleHeader(request, "If-Match", true)
	if err != nil || len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, ErrInvalidRequest
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != value[1:len(value)-1] {
		return 0, ErrInvalidRequest
	}
	return revision, nil
}

func singleHeader(request *http.Request, name string, required bool) (string, error) {
	values, found := request.Header[http.CanonicalHeaderKey(name)]
	if !found {
		if required {
			return "", ErrInvalidRequest
		}
		return "", nil
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", ErrInvalidRequest
	}
	return values[0], nil
}

func requestIdentifier(request *http.Request) (string, bool) {
	value, err := singleHeader(request, "X-Request-ID", false)
	if err != nil {
		return generatedRequestID(), false
	}
	if value == "" {
		return generatedRequestID(), true
	}
	return value, metadataPattern.MatchString(value)
}

func generatedRequestID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "request-unavailable"
	}
	return "request-" + hex.EncodeToString(value)
}

func strictUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidRequest
	}
	return parsed, nil
}

func parseRecordType(value string) (dnscheck.RecordType, error) {
	switch value {
	case "A":
		return dnscheck.RecordA, nil
	case "AAAA":
		return dnscheck.RecordAAAA, nil
	case "CNAME":
		return dnscheck.RecordCNAME, nil
	default:
		return 0, ErrInvalidRequest
	}
}

func mapIAMError(err error) error {
	if errors.Is(err, ErrUnauthenticated) {
		return ErrUnauthenticated
	}
	if errors.Is(err, ErrPermissionDenied) || errors.Is(err, dnsreconcile.ErrPermissionDenied) {
		return ErrPermissionDenied
	}
	return ErrUnavailable
}

func isNil(value any) bool {
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
