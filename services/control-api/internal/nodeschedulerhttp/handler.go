package nodeschedulerhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

const maxRequestBytes = int64(128 << 10)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var (
	ErrInvalidHandlerConfig = errors.New("invalid node scheduling HTTP configuration")
	ErrUnauthenticated      = errors.New("node scheduling authentication required")
	ErrInvalidRequest       = errors.New("invalid node scheduling HTTP request")
	// ErrInvalidSortOrder：显式 sort_order:0（契约最小为 1）。
	ErrInvalidSortOrder = errors.New("node scheduling sort order must be at least 1")
)

type Service interface {
	List(context.Context, nodescheduler.Actor) ([]nodescheduler.LineGroupRevision, error)
	PutGroup(context.Context, nodescheduler.Actor, nodescheduler.PutGroupRequest) (nodescheduler.WriteResult, error)
	DeleteGroup(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.DeleteResult, error)
	GetCurrent(context.Context, nodescheduler.Actor, uuid.UUID) (nodescheduler.LineGroupRevision, error)
	GetRevision(context.Context, nodescheduler.Actor, uuid.UUID, int64) (nodescheduler.LineGroupRevision, error)
	DecideCurrent(context.Context, nodescheduler.Actor, uuid.UUID, nodescheduler.DecisionRequest) (nodescheduler.Decision, error)
	CreateTargetSnapshotForNodes(context.Context, nodescheduler.Actor, uuid.UUID, int64, []uuid.UUID, string, string) (nodescheduler.TargetSnapshot, error)
	GetTargetSnapshot(context.Context, nodescheduler.Actor, uuid.UUID, int64) (nodescheduler.TargetSnapshot, error)
	Rollback(context.Context, nodescheduler.Actor, uuid.UUID, int64, int64, string, string) (nodescheduler.WriteResult, error)
	ListL2Configs(context.Context, nodescheduler.Actor) ([]nodescheduler.L2Config, error)
	GetL2Config(context.Context, nodescheduler.Actor, uuid.UUID) (nodescheduler.L2Config, error)
	PutL2Config(context.Context, nodescheduler.Actor, nodescheduler.L2ConfigWriteRequest) (nodescheduler.L2ConfigWriteResult, error)
	DeleteL2Config(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error)
	ListL2Conditions(context.Context, nodescheduler.Actor) ([]nodescheduler.L2Condition, error)
	PutL2Condition(context.Context, nodescheduler.Actor, nodescheduler.L2ConditionWriteRequest) (nodescheduler.L2ConditionWriteResult, error)
	DeleteL2Condition(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error)
	ListL2Nodes(context.Context, nodescheduler.Actor, uuid.UUID) ([]nodescheduler.L2Node, error)
	ListAvailableL2Nodes(context.Context, nodescheduler.Actor, uuid.UUID) ([]nodescheduler.L2NodeCandidate, error)
	AddL2Nodes(context.Context, nodescheduler.Actor, nodescheduler.L2NodeAddRequest) (nodescheduler.L2NodeAddResult, error)
	PutL2Node(context.Context, nodescheduler.Actor, nodescheduler.L2NodeWriteRequest) (nodescheduler.L2NodeWriteResult, error)
	DeleteL2Node(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error)
}

type lineGroupStatisticsService interface {
	ListStatistics(context.Context, nodescheduler.Actor, []nodescheduler.LineGroupRevision) (map[uuid.UUID]nodescheduler.LineGroupStatistics, error)
}

// platformDefaultService is optional so test doubles of Service need not
// implement it (migration 533).
type platformDefaultService interface {
	SetPlatformDefault(context.Context, nodescheduler.Actor, uuid.UUID, bool, string) (nodescheduler.LineGroupRevision, error)
}

type Authenticator interface {
	Authenticate(*http.Request) (nodescheduler.Actor, error)
}

type Handler struct {
	service       Service
	authenticator Authenticator
	mux           *http.ServeMux
}

type requestContextKey string

const requestIDSuppliedKey requestContextKey = "node-scheduling-request-id-supplied"

func NewHandler(service Service, authenticator Authenticator) (*Handler, error) {
	if service == nil || authenticator == nil {
		return nil, ErrInvalidHandlerConfig
	}
	if _, ok := service.(lineGroupStatisticsService); !ok {
		return nil, ErrInvalidHandlerConfig
	}
	handler := &Handler{service: service, authenticator: authenticator, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/node-line-groups", handler.collection)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}", handler.item)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}/revisions/{revision}", handler.revision)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}/decisions", handler.decision)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}/target-snapshots", handler.targetSnapshot)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}/rollback", handler.rollback)
	handler.mux.HandleFunc("/v1/node-line-groups/{id}/platform-default", handler.platformDefault)
	handler.mux.HandleFunc("/v1/l2-configs", handler.l2ConfigCollection)
	handler.mux.HandleFunc("/v1/l2-configs/{id}", handler.l2ConfigItem)
	handler.mux.HandleFunc("/v1/l2-conds", handler.l2ConditionCollection)
	handler.mux.HandleFunc("/v1/l2-conds/{id}", handler.l2ConditionItem)
	handler.mux.HandleFunc("/v1/l2-nodes", handler.l2NodeCollection)
	handler.mux.HandleFunc("/v1/l2-nodes/{id}", handler.l2NodeItem)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	invalidSingletons := invalidSingletonHeaders(request)
	requestIDValues := request.Header.Values("X-Request-ID")
	requestIDSupplied := len(requestIDValues) == 1 && metadataPattern.MatchString(requestIDValues[0])
	invalidSingletons = invalidSingletons || len(requestIDValues) > 0 && !requestIDSupplied
	requestID := newRequestID()
	if requestIDSupplied {
		requestID = requestIDValues[0]
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if invalidSingletons {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 8*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, requestIDSuppliedKey, requestIDSupplied)
	handler.mux.ServeHTTP(response, request.WithContext(ctx))
}

func (handler *Handler) collection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		items, err := handler.service.List(request.Context(), actor)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		statistics, err := handler.service.(lineGroupStatisticsService).ListStatistics(request.Context(), actor, items)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		views := make([]lineGroupDTO, len(items))
		for index, item := range items {
			itemStatistics, ok := statistics[item.GroupID]
			if !ok {
				handler.writeError(response, request, ErrInvalidHandlerConfig)
				return
			}
			views[index] = lineGroupView(item)
			views[index].Statistics = &lineGroupStatisticsDTO{
				NodeCount: itemStatistics.NodeCount, SiteCount: itemStatistics.SiteCount,
				ForwardCount: itemStatistics.ForwardCount,
			}
		}
		handler.writeJSON(response, http.StatusOK, map[string]any{"items": views})
	case http.MethodPost:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, true)
		if !ok {
			return
		}
		var body lineGroupWriteBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.zeroSortOrder {
			handler.writeError(response, request, ErrInvalidSortOrder)
			return
		}
		if err := lineGroupBodyError(body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.PutGroup(request.Context(), actor, body.request(uuid.Nil, revision, key, requestID))
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Group.Revision))
		response.Header().Set("Location", "/v1/node-line-groups/"+result.Group.GroupID.String())
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusCreated, map[string]any{"group": lineGroupView(result.Group), "replayed": result.Replayed})
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) item(response http.ResponseWriter, request *http.Request) {
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		group, err := handler.service.GetCurrent(request.Context(), actor, groupID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(group.Revision))
		handler.writeJSON(response, http.StatusOK, lineGroupView(group))
	case http.MethodPut:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		var body lineGroupWriteBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.zeroSortOrder {
			handler.writeError(response, request, ErrInvalidSortOrder)
			return
		}
		if err := lineGroupBodyError(body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.PutGroup(request.Context(), actor, body.request(groupID, revision, key, requestID))
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Group.Revision))
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusOK, map[string]any{"group": lineGroupView(result.Group), "replayed": result.Replayed})
	case http.MethodDelete:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		result, err := handler.service.DeleteGroup(request.Context(), actor, groupID, revision, key, requestID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Revision))
		setReplay(response, result.Replayed)
		response.WriteHeader(http.StatusNoContent)
	default:
		handler.methodNotAllowed(response, request, "GET, PUT, DELETE")
	}
}

func (handler *Handler) revision(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	actor, ok := handler.actor(response, request, false)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	revision, err := strconv.ParseInt(request.PathValue("revision"), 10, 64)
	if err != nil || revision < 1 {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	group, err := handler.service.GetRevision(request.Context(), actor, groupID, revision)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(group.Revision))
	handler.writeJSON(response, http.StatusOK, lineGroupView(group))
}

type decisionBody struct {
	Selector      *nodescheduler.Selector `json:"selector"`
	RequestedMode string                  `json:"requested_mode"`
	StableKey     string                  `json:"stable_key"`
}

func (handler *Handler) decision(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	if supplied, _ := request.Context().Value(requestIDSuppliedKey).(bool); !supplied {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	actor, ok := handler.actor(response, request, false)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	var body decisionBody
	if !handler.decode(response, request, &body) {
		return
	}
	if body.Selector == nil || body.StableKey == "" || !utf8.ValidString(body.StableKey) || utf8.RuneCountInString(body.StableKey) > 1024 ||
		body.RequestedMode != nodescheduler.StrategyWeightedBaseline &&
			body.RequestedMode != nodescheduler.StrategyWeightedRendezvous &&
			body.RequestedMode != nodescheduler.StrategyP2CLeastLoaded {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.DecideCurrent(request.Context(), actor, groupID, nodescheduler.DecisionRequest{
		Selector: *body.Selector, Strategy: body.RequestedMode, StableKey: body.StableKey,
		RequestID: request.Header.Get("X-Request-ID"),
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	effective := result.Strategy
	if result.Fallback {
		effective = nodescheduler.StrategyWeightedBaseline
	}
	candidates := make([]endpointDTO, len(result.Plan.Candidates))
	for index, endpoint := range result.Plan.Candidates {
		candidates[index] = endpointView(endpoint)
	}
	standby := make([]endpointDTO, len(result.Plan.Standby))
	for index, endpoint := range result.Plan.Standby {
		standby[index] = endpointView(endpoint)
	}
	handler.writeJSON(response, http.StatusOK, map[string]any{
		"endpoint": endpointView(result.Endpoint), "requested_mode": body.RequestedMode,
		"effective_mode": effective, "reason": result.Reason, "fallback": result.Fallback,
		"priority": result.Plan.Priority, "candidates": candidates, "standby": standby,
		"snapshot": decisionSnapshotView(result.Plan),
	})
}

func decisionSnapshotView(plan nodescheduler.Plan) map[string]any {
	evaluations := make([]map[string]any, len(plan.Evaluations))
	for index, evaluation := range plan.Evaluations {
		evaluations[index] = map[string]any{
			"endpoint":            endpointView(evaluation.Endpoint),
			"disposition":         evaluation.Disposition,
			"health_status":       evaluation.Endpoint.Health.Status,
			"health_row_revision": evaluation.Endpoint.Health.RowRevision,
			"last_observed_at":    evaluation.Endpoint.Health.LastObservedAt,
			"last_received_at":    evaluation.Endpoint.Health.LastReceivedAt,
		}
	}
	var selectedPriority any
	if len(plan.Candidates) > 0 {
		selectedPriority = plan.Priority
	}
	return map[string]any{
		"tenant_scope_id":      plan.TenantScopeID.String(),
		"group_id":             plan.GroupID.String(),
		"revision":             plan.Revision,
		"configuration_digest": hex.EncodeToString(plan.ConfigurationDigest),
		"plan_digest":          hex.EncodeToString(plan.Digest[:]),
		"selector":             plan.Selector,
		"evaluated_at":         plan.EvaluatedAt,
		"selected_priority":    selectedPriority,
		"tier_reason":          plan.TierReason,
		"endpoint_evaluations": evaluations,
	}
}

type snapshotBody struct {
	SourceRevision int64       `json:"source_revision"`
	NodeIDs        []uuid.UUID `json:"node_ids"`
}

func (handler *Handler) targetSnapshot(response http.ResponseWriter, request *http.Request) {
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		values := request.URL.Query()["source_revision"]
		if len(values) != 1 {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		revision, err := strconv.ParseInt(values[0], 10, 64)
		if err != nil || revision < 1 {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.GetTargetSnapshot(request.Context(), actor, groupID, revision)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, http.StatusOK, targetSnapshotView(result))
	case http.MethodPost:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		key, requestID, ok := handler.metadataWithoutRevision(response, request)
		if !ok {
			return
		}
		var body snapshotBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.SourceRevision < 1 || len(body.NodeIDs) < 1 || len(body.NodeIDs) > 10000 {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.CreateTargetSnapshotForNodes(
			request.Context(), actor, groupID, body.SourceRevision, body.NodeIDs, key, requestID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusCreated, targetSnapshotView(result))
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func targetSnapshotView(result nodescheduler.TargetSnapshot) map[string]any {
	return map[string]any{
		"id": result.Reference.ID, "revision": result.Reference.Revision,
		"tenant_scope_id": result.TenantScopeID, "source_line_group_id": result.SourceLineGroupID,
		"source_revision":             result.SourceRevision,
		"source_configuration_digest": hex.EncodeToString(result.SourceConfigurationDigest),
		"node_set_digest":             hex.EncodeToString(result.Reference.SHA256[:]), "node_ids": result.NodeIDs,
	}
}

type rollbackBody struct {
	SourceRevision int64 `json:"source_revision"`
}

func (handler *Handler) rollback(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	actor, ok := handler.actor(response, request, true)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	revision, key, requestID, ok := handler.writeMetadata(response, request, false)
	if !ok {
		return
	}
	var body rollbackBody
	if !handler.decode(response, request, &body) {
		return
	}
	if body.SourceRevision < 1 {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.Rollback(request.Context(), actor, groupID, body.SourceRevision, revision, key, requestID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Group.Revision))
	setReplay(response, result.Replayed)
	handler.writeJSON(response, http.StatusOK, map[string]any{"group": lineGroupView(result.Group), "replayed": result.Replayed})
}

func (handler *Handler) platformDefault(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	service, supported := handler.service.(platformDefaultService)
	if !supported {
		handler.writeError(response, request, ErrInvalidHandlerConfig)
		return
	}
	actor, ok := handler.actor(response, request, true)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	_, requestID, ok := handler.metadataWithoutRevision(response, request)
	if !ok {
		return
	}
	var body platformDefaultBody
	if !handler.decode(response, request, &body) {
		return
	}
	if body.IsPlatformDefault == nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	group, err := service.SetPlatformDefault(request.Context(), actor, groupID, *body.IsPlatformDefault, requestID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(group.Revision))
	handler.writeJSON(response, http.StatusOK, map[string]any{"group": lineGroupView(group)})
}

func (handler *Handler) actor(response http.ResponseWriter, request *http.Request, write bool) (nodescheduler.Actor, bool) {
	actor, err := handler.authenticator.Authenticate(request)
	if err != nil {
		handler.writeError(response, request, err)
		return nodescheduler.Actor{}, false
	}
	target := request.URL.Query().Get("target_scope_id")
	if len(request.URL.Query()["target_scope_id"]) > 1 {
		handler.writeError(response, request, ErrInvalidRequest)
		return nodescheduler.Actor{}, false
	}
	if actor.ScopeKind == "platform" {
		if target == "" {
			actor.TargetScopeID = actor.ScopeID
			return actor, true
		}
		parsed, err := uuid.Parse(target)
		if err != nil || parsed == uuid.Nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return nodescheduler.Actor{}, false
		}
		if write && parsed != actor.ScopeID {
			handler.writeError(response, request, nodescheduler.ErrPlatformWriteDenied)
			return nodescheduler.Actor{}, false
		}
		actor.TargetScopeID = parsed
		return actor, true
	}
	if actor.ScopeKind != "tenant" {
		handler.writeError(response, request, ErrUnauthenticated)
		return nodescheduler.Actor{}, false
	}
	if target != "" {
		parsed, err := uuid.Parse(target)
		if err != nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return nodescheduler.Actor{}, false
		}
		if parsed != actor.ScopeID {
			handler.writeError(response, request, nodescheduler.ErrPermissionDenied)
			return nodescheduler.Actor{}, false
		}
	}
	actor.TargetScopeID = actor.ScopeID
	return actor, true
}

func (handler *Handler) writeMetadata(response http.ResponseWriter, request *http.Request, create bool) (int64, string, string, bool) {
	key, requestID, ok := handler.metadataWithoutRevision(response, request)
	if !ok {
		return 0, "", "", false
	}
	revision, ok := parseIfMatch(request.Header.Values("If-Match"), create)
	if !ok {
		handler.writeError(response, request, ErrInvalidRequest)
		return 0, "", "", false
	}
	return revision, key, requestID, true
}

func (handler *Handler) metadataWithoutRevision(response http.ResponseWriter, request *http.Request) (string, string, bool) {
	keys, requestIDs := request.Header.Values("Idempotency-Key"), request.Header.Values("X-Request-ID")
	supplied, _ := request.Context().Value(requestIDSuppliedKey).(bool)
	if !supplied || len(keys) != 1 || len(requestIDs) != 1 || !metadataPattern.MatchString(keys[0]) || !metadataPattern.MatchString(requestIDs[0]) {
		handler.writeError(response, request, ErrInvalidRequest)
		return "", "", false
	}
	return keys[0], requestIDs[0], true
}

func parseIfMatch(values []string, create bool) (int64, bool) {
	if len(values) != 1 || len(values[0]) < 3 || values[0][0] != '"' || values[0][len(values[0])-1] != '"' {
		return 0, false
	}
	revision, err := strconv.ParseInt(values[0][1:len(values[0])-1], 10, 64)
	if err != nil || create && revision != 0 || !create && revision < 1 {
		return 0, false
	}
	return revision, true
}

func (handler *Handler) decode(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		handler.writeError(response, request, ErrInvalidRequest)
		return false
	}
	reader := http.MaxBytesReader(response, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(reader)
	if err != nil || !utf8.Valid(raw) {
		handler.writeError(response, request, ErrInvalidRequest)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		handler.writeError(response, request, ErrInvalidRequest)
		return false
	}
	return true
}

func invalidSingletonHeaders(request *http.Request) bool {
	for _, name := range []string{"Authorization", "X-Request-ID", "Idempotency-Key", "If-Match"} {
		values := request.Header.Values(name)
		if len(values) > 1 || len(values) == 1 && strings.Contains(values[0], ",") {
			return true
		}
	}
	return false
}

func (handler *Handler) pathUUID(response http.ResponseWriter, request *http.Request, name string) (uuid.UUID, bool) {
	value, err := uuid.Parse(request.PathValue(name))
	if err != nil || value == uuid.Nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return uuid.Nil, false
	}
	return value, true
}

func (handler *Handler) methodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	handler.writeJSON(response, http.StatusMethodNotAllowed,
		errorBody("node_scheduling_invalid_request", "method not allowed", request.Header.Get("X-Request-ID")))
}

// lineGroupBodyError is the first field the handler itself refuses (nil: valid).
func lineGroupBodyError(body lineGroupWriteBody) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidRequest, name, reason) }
	switch {
	case strings.TrimSpace(body.Name) == "":
		return field("name", fielderr.Required)
	case body.HealthPolicy == nil:
		return field("health_policy", fielderr.Required)
	case body.L2ConfigID != nil && *body.L2ConfigID == uuid.Nil:
		return field("l2_config_id", fielderr.Invalid)
	}
	for index, endpoint := range body.Endpoints {
		if endpoint.ID == uuid.Nil {
			return field("endpoints["+strconv.Itoa(index)+"].id", fielderr.Required)
		}
		if endpoint.NodeID == uuid.Nil {
			return field("endpoints["+strconv.Itoa(index)+"].node_id", fielderr.Required)
		}
	}
	return nil
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	status, code, message := errorMapping(err)
	body := errorBody(code, message, request.Header.Get("X-Request-ID"))
	// A located refusal keeps its status and code and names the field.
	if located, ok := fielderr.As(err); ok && status == http.StatusBadRequest {
		body["error"]["details"] = map[string]string{"field": located.Field, "reason": located.Reason}
	}
	handler.writeJSON(response, status, body)
}

func errorMapping(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, nodescheduler.ErrCredentialInvalid):
		return http.StatusUnauthorized, "node_scheduling_unauthenticated", "authentication required"
	case errors.Is(err, nodescheduler.ErrPlatformWriteDenied):
		return http.StatusForbidden, "node_scheduling_platform_write_forbidden", "platform credentials cannot write targeted tenant node scheduling facts"
	case errors.Is(err, nodescheduler.ErrPermissionDenied):
		return http.StatusForbidden, "node_scheduling_permission_denied", "permission denied"
	case errors.Is(err, nodescheduler.ErrNotFound):
		return http.StatusNotFound, "node_scheduling_not_found", "node line group not found"
	case errors.Is(err, nodescheduler.ErrNameConflict):
		return http.StatusConflict, "node_scheduling_name_conflict", "node line group name conflict"
	case errors.Is(err, nodescheduler.ErrRevisionConflict):
		return http.StatusPreconditionFailed, "node_scheduling_revision_conflict", "node line group revision conflict"
	case errors.Is(err, nodescheduler.ErrIdempotencyConflict):
		return http.StatusConflict, "node_scheduling_idempotency_conflict", "idempotency key conflict"
	case errors.Is(err, nodescheduler.ErrReferenceConflict):
		return http.StatusConflict, "node_scheduling_reference_conflict", "node line group is referenced by active configuration"
	case errors.Is(err, nodescheduler.ErrNoHealthyEndpoint):
		return http.StatusConflict, "node_scheduling_no_healthy_endpoint", "no healthy endpoint"
	case errors.Is(err, nodescheduler.ErrTopologyCycle):
		return http.StatusConflict, nodescheduler.ReasonTopologyCycleRejected, "node topology is not a two-level DAG"
	case errors.Is(err, nodescheduler.ErrTargetSnapshotConflict):
		return http.StatusConflict, "node_scheduling_target_snapshot_conflict", "target snapshot conflict"
	case errors.Is(err, nodescheduler.ErrTargetSnapshotUnavailable):
		return http.StatusConflict, "node_scheduling_target_snapshot_unavailable", "target snapshot unavailable"
	case errors.Is(err, nodescheduler.ErrEndpointAddressNotOnNode):
		return http.StatusUnprocessableEntity, "node_scheduling_endpoint_address_not_on_node", "endpoint address is not an IP of its node"
	case errors.As(err, new(*nodescheduler.L2RuleRegexError)):
		// The message names the rule (1-based) the page marks.
		var invalid *nodescheduler.L2RuleRegexError
		errors.As(err, &invalid)
		return http.StatusUnprocessableEntity, "l2_condition_invalid_regex", fmt.Sprintf("rule %d", invalid.Index+1)
	case errors.Is(err, ErrInvalidSortOrder):
		return http.StatusBadRequest, "node_scheduling_invalid_sort_order", "sort_order must be an integer of at least 1"
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, nodescheduler.ErrInvalidInput):
		return http.StatusBadRequest, "node_scheduling_invalid_request", "request is invalid"
	default:
		return http.StatusServiceUnavailable, "node_scheduling_unavailable", "node scheduling unavailable"
	}
}

func errorBody(code, message, requestID string) map[string]map[string]any {
	return map[string]map[string]any{"error": {"code": code, "message": message, "request_id": requestID}}
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(response, `{"error":{"code":"node_scheduling_unavailable","message":"node scheduling unavailable","request_id":""}}`, http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func quoteRevision(revision int64) string { return fmt.Sprintf("\"%d\"", revision) }

func setReplay(response http.ResponseWriter, replayed bool) {
	if replayed {
		response.Header().Set("Idempotency-Replayed", "true")
	}
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(value[:])
}
