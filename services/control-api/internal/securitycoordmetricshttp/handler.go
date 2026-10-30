package securitycoordmetricshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/google/uuid"
)

const (
	Route          = "/v1/admin/security/coordination/metrics"
	SchemaVersion  = "security_coordination_metrics.v1"
	PermissionRead = "security_policies.read"
)

var (
	ErrInvalidDependencies = errors.New("security coordination metrics HTTP dependencies are invalid")
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type SnapshotFunc func() securitycoordmetrics.Snapshot
type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	CCSnapshot          SnapshotFunc
	FirewallSnapshot    SnapshotFunc
	AuthenticateSession AuthenticateSessionFunc
}

type Handler struct {
	ccSnapshot          SnapshotFunc
	firewallSnapshot    SnapshotFunc
	authenticateSession AuthenticateSessionFunc
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.CCSnapshot == nil || dependencies.FirewallSnapshot == nil || dependencies.AuthenticateSession == nil {
		return nil, ErrInvalidDependencies
	}
	return &Handler{
		ccSnapshot: dependencies.CCSnapshot, firewallSnapshot: dependencies.FirewallSnapshot,
		authenticateSession: dependencies.AuthenticateSession,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, validRequestID := requestID(request)
	response.Header().Set("X-Request-ID", requestID)

	if request.URL.Path != Route {
		writeError(response, http.StatusNotFound, "security_coordination_metrics_not_found", requestID)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeError(response, http.StatusMethodNotAllowed, "security_coordination_metrics_method_not_allowed", requestID)
		return
	}
	if !validRequestID || request.URL.RawQuery != "" || request.ContentLength != 0 ||
		(request.Body != nil && request.Body != http.NoBody) || len(request.TransferEncoding) != 0 || spoofedActor(request) {
		writeError(response, http.StatusBadRequest, "security_coordination_metrics_invalid_request", requestID)
		return
	}
	if len(request.Header.Values("X-API-Key")) != 0 {
		writeError(response, http.StatusUnauthorized, "security_coordination_metrics_authentication_required", requestID)
		return
	}
	token, ok := bearerToken(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "security_coordination_metrics_authentication_required", requestID)
		return
	}
	session, err := handler.authenticateSession(request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			writeError(response, http.StatusUnauthorized, "security_coordination_metrics_authentication_required", requestID)
			return
		}
		writeError(response, http.StatusServiceUnavailable, "security_coordination_metrics_unavailable", requestID)
		return
	}
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		writeError(response, http.StatusUnauthorized, "security_coordination_metrics_authentication_required", requestID)
		return
	}
	if principal.ScopeKind != "platform" || principal.TenantID != nil ||
		!hasPermission(principal.Permissions, "platform.admin") || !hasPermission(principal.Permissions, PermissionRead) {
		writeError(response, http.StatusForbidden, "security_coordination_metrics_permission_denied", requestID)
		return
	}
	cc := handler.ccSnapshot().CC
	firewall := handler.firewallSnapshot().Firewall
	writeJSON(response, http.StatusOK, metricsResponse{
		Schema: SchemaVersion,
		CC: ccResponse{
			ObserveRuns: cc.ObserveRuns, Accepted: cc.Accepted, Duplicates: cc.Duplicates, Rejected: cc.Rejected, Queued: cc.Queued,
			CapacityRejected: cc.CapacityRejected, ScopeRejected: cc.ScopeRejected, DependencyUnavailable: cc.DependencyUnavailable,
			Invalid: cc.Invalid, Conflict: cc.Conflict, CoordinationRuns: cc.CoordinationRuns,
			CoordinationClaimed: cc.CoordinationClaimed, CoordinationPublished: cc.CoordinationPublished,
			CoordinationRetryable: cc.CoordinationRetryable, ActivationActive: cc.ActivationActive,
			ActivationFailed: cc.ActivationFailed, FalsePositiveReleases: cc.FalsePositiveReleases,
			ReleaseReplays: cc.ReleaseReplays, ReleaseRejected: cc.ReleaseRejected,
		},
		Firewall: firewallResponse{
			DispatchRuns: firewall.DispatchRuns, Claimed: firewall.Claimed, Published: firewall.Published,
			PubACKDuplicates: firewall.PubACKDuplicates, Retryable: firewall.Retryable, Exhausted: firewall.Exhausted,
			PublishTimeout: firewall.PublishTimeout, PublishUnknown: firewall.PublishUnknown,
			PubACKMissing: firewall.PubACKMissing, PubACKRejected: firewall.PubACKRejected,
			IntegrityRejected: firewall.IntegrityRejected, DependencyUnavailable: firewall.DependencyUnavailable,
			ACKSettled: firewall.ACKSettled, ACKReplayed: firewall.ACKReplayed, ACKRescued: firewall.ACKRescued,
			ACKRejected: firewall.ACKRejected, Applied: firewall.Applied, Failed: firewall.Failed,
			RolledBack: firewall.RolledBack, Recoveries: firewall.Recoveries, GlobalActive: firewall.GlobalActive,
			GlobalPartial: firewall.GlobalPartial, GlobalFailed: firewall.GlobalFailed, GlobalRolledBack: firewall.GlobalRolledBack,
		},
	})
}

func bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && len(token) < 8192 && !strings.ContainsFunc(token, unicode.IsSpace)
}

func requestID(request *http.Request) (string, bool) {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 0 {
		return uuid.NewString(), true
	}
	if len(values) != 1 || !requestIDPattern.MatchString(values[0]) {
		return uuid.NewString(), false
	}
	return values[0], true
}

func spoofedActor(request *http.Request) bool {
	for _, name := range []string{"X-Scope-Kind", "X-Tenant-ID", "X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions"} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func hasPermission(permissions []string, required string) bool {
	for _, permission := range permissions {
		if permission == required {
			return true
		}
	}
	return false
}

type metricsResponse struct {
	Schema   string           `json:"schema"`
	CC       ccResponse       `json:"cc"`
	Firewall firewallResponse `json:"firewall"`
}

type ccResponse struct {
	ObserveRuns           uint64 `json:"observe_runs"`
	Accepted              uint64 `json:"accepted"`
	Duplicates            uint64 `json:"duplicates"`
	Rejected              uint64 `json:"rejected"`
	Queued                uint64 `json:"queued"`
	CapacityRejected      uint64 `json:"capacity_rejected"`
	ScopeRejected         uint64 `json:"scope_rejected"`
	DependencyUnavailable uint64 `json:"dependency_unavailable"`
	Invalid               uint64 `json:"invalid"`
	Conflict              uint64 `json:"conflict"`
	CoordinationRuns      uint64 `json:"coordination_runs"`
	CoordinationClaimed   uint64 `json:"coordination_claimed"`
	CoordinationPublished uint64 `json:"coordination_published"`
	CoordinationRetryable uint64 `json:"coordination_retryable"`
	ActivationActive      uint64 `json:"activation_active"`
	ActivationFailed      uint64 `json:"activation_failed"`
	FalsePositiveReleases uint64 `json:"false_positive_releases"`
	ReleaseReplays        uint64 `json:"release_replays"`
	ReleaseRejected       uint64 `json:"release_rejected"`
}

type firewallResponse struct {
	DispatchRuns          uint64 `json:"dispatch_runs"`
	Claimed               uint64 `json:"claimed"`
	Published             uint64 `json:"published"`
	PubACKDuplicates      uint64 `json:"puback_duplicates"`
	Retryable             uint64 `json:"retryable"`
	Exhausted             uint64 `json:"exhausted"`
	PublishTimeout        uint64 `json:"publish_timeout"`
	PublishUnknown        uint64 `json:"publish_unknown"`
	PubACKMissing         uint64 `json:"puback_missing"`
	PubACKRejected        uint64 `json:"puback_rejected"`
	IntegrityRejected     uint64 `json:"integrity_rejected"`
	DependencyUnavailable uint64 `json:"dependency_unavailable"`
	ACKSettled            uint64 `json:"ack_settled"`
	ACKReplayed           uint64 `json:"ack_replayed"`
	ACKRescued            uint64 `json:"ack_rescued"`
	ACKRejected           uint64 `json:"ack_rejected"`
	Applied               uint64 `json:"applied"`
	Failed                uint64 `json:"failed"`
	RolledBack            uint64 `json:"rolled_back"`
	Recoveries            uint64 `json:"recoveries"`
	GlobalActive          uint64 `json:"global_active"`
	GlobalPartial         uint64 `json:"global_partial"`
	GlobalFailed          uint64 `json:"global_failed"`
	GlobalRolledBack      uint64 `json:"global_rolled_back"`
}

func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
