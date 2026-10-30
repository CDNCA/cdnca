package challengepolicy

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/google/uuid"
)

type PublicationStatus struct {
	PolicyID          uuid.UUID                               `json:"policy_id"`
	PolicyRevision    int64                                   `json:"policy_revision"`
	RolloutID         uuid.UUID                               `json:"rollout_id"`
	ConfigVersionID   uuid.UUID                               `json:"config_version_id"`
	State             string                                  `json:"state"`
	Reason            string                                  `json:"reason"`
	Total             int                                     `json:"total"`
	Pending           int                                     `json:"pending"`
	Running           int                                     `json:"running"`
	Healthy           int                                     `json:"healthy"`
	Failed            int                                     `json:"failed"`
	Cancelled         int                                     `json:"cancelled"`
	Superseded        int                                     `json:"superseded"`
	ConfigPublication *challengepublication.ConfigPublication `json:"config_publication,omitempty"`
}

type PublicationRequest struct {
	Actor            Actor
	TenantScopeID    uuid.UUID
	PolicyID         uuid.UUID
	ExpectedRevision int64
	RolloutID        uuid.UUID
	Metadata         WriteMetadata
}

type PublicationDomain interface {
	Publish(context.Context, PublicationRequest) (PublicationStatus, error)
	Status(context.Context, PublicationRequest) (PublicationStatus, error)
	Promote(context.Context, PublicationRequest) (PublicationStatus, error)
}

type PublicationHandler struct {
	base   *Handler
	domain PublicationDomain
	mux    *http.ServeMux
}

type publicationRoute uint8

const (
	publicationCollectionRoute publicationRoute = iota + 1
	publicationStatusRoute
	publicationPromoteRoute
)

func NewPublicationHandler(authenticator Authenticator, domain PublicationDomain) (*PublicationHandler, error) {
	if isNilDependency(authenticator) || isNilDependency(domain) {
		return nil, ErrInvalidHandlerConfig
	}
	handler := &PublicationHandler{base: &Handler{authenticator: authenticator}, domain: domain, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications", handler.collection)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}", handler.status)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/challenge-policies/{policy_id}/publications/{rollout_id}/promote", handler.promote)
	return handler, nil
}

func (handler *PublicationHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	route := classifyPublicationRoute(request)
	if handler == nil || route == 0 {
		http.NotFound(response, request)
		return
	}
	for _, name := range []string{"Authorization", "X-Request-ID", "X-Trace-ID", "Idempotency-Key", "If-Match"} {
		if len(request.Header.Values(name)) > 1 {
			handler.base.writeError(response, request, ErrInvalidInput)
			return
		}
	}
	if len(request.URL.Query()) != 0 {
		handler.base.writeError(response, request, ErrInvalidInput)
		return
	}
	metadata, err := requestMetadata(request, route != publicationStatusRoute)
	if err != nil {
		handler.base.writeError(response, request, ErrInvalidInput)
		return
	}
	response.Header().Set("X-Request-ID", metadata.RequestID)
	response.Header().Set("X-Trace-ID", metadata.TraceID)
	handler.mux.ServeHTTP(response, request)
}

func (handler *PublicationHandler) collection(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.base.writeMethodNotAllowed(response, request, http.MethodPost)
		return
	}
	command, ok := handler.command(response, request, false)
	if !ok {
		return
	}
	result, err := handler.domain.Publish(request.Context(), command)
	handler.writeResult(response, request, http.StatusAccepted, result, err)
}

func (handler *PublicationHandler) status(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		handler.base.writeMethodNotAllowed(response, request, http.MethodGet)
		return
	}
	command, ok := handler.command(response, request, true)
	if !ok {
		return
	}
	result, err := handler.domain.Status(request.Context(), command)
	handler.writeResult(response, request, http.StatusOK, result, err)
}

func (handler *PublicationHandler) promote(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.base.writeMethodNotAllowed(response, request, http.MethodPost)
		return
	}
	command, ok := handler.command(response, request, true)
	if !ok {
		return
	}
	result, err := handler.domain.Promote(request.Context(), command)
	handler.writeResult(response, request, http.StatusOK, result, err)
}

func (handler *PublicationHandler) command(response http.ResponseWriter, request *http.Request, rollout bool) (PublicationRequest, bool) {
	actor, targetScopeID, policyID, ok := handler.base.authorizeResource(response, request)
	if !ok {
		return PublicationRequest{}, false
	}
	metadata, err := requestMetadata(request, request.Method == http.MethodPost)
	if err != nil {
		handler.base.writeError(response, request, ErrInvalidInput)
		return PublicationRequest{}, false
	}
	command := PublicationRequest{Actor: actor, TenantScopeID: targetScopeID, PolicyID: policyID, Metadata: metadata}
	if request.Method == http.MethodPost {
		command.ExpectedRevision, err = expectedRevision(request)
		if err != nil || !hasJSONContentType(request) || !emptyCommandBody(response, request) {
			handler.base.writeError(response, request, ErrInvalidInput)
			return PublicationRequest{}, false
		}
	} else if !emptyBody(request) {
		handler.base.writeError(response, request, ErrInvalidInput)
		return PublicationRequest{}, false
	}
	if rollout {
		command.RolloutID, err = strictUUID(request.PathValue("rollout_id"))
		if err != nil {
			handler.base.writeError(response, request, ErrInvalidInput)
			return PublicationRequest{}, false
		}
	}
	return command, true
}

func (handler *PublicationHandler) writeResult(response http.ResponseWriter, request *http.Request, status int, result PublicationStatus, err error) {
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if !validPublicationStatus(result) {
		handler.base.writeError(response, request, ErrUnavailable)
		return
	}
	handler.base.writeJSON(response, request, status, result)
}

func (handler *PublicationHandler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, challengepublication.ErrExternalAdapterUnavailable):
		handler.base.writeAPIError(response, request, http.StatusUnprocessableEntity,
			"challenge_external_adapter_unavailable", "external challenge adapter is unavailable")
	case errors.Is(err, challengepublication.ErrRolloutNotHealthy), errors.Is(err, challengepublication.ErrRolloutFailed):
		handler.base.writeAPIError(response, request, http.StatusConflict,
			"challenge_publication_not_ready", "challenge publication is not ready")
	default:
		handler.base.writeError(response, request, err)
	}
}

func validPublicationStatus(value PublicationStatus) bool {
	if value.PolicyID == uuid.Nil || value.PolicyRevision < 1 || value.RolloutID == uuid.Nil ||
		value.ConfigVersionID == uuid.Nil || value.Total < 1 || value.Total > 10000 || value.Pending < 0 ||
		value.Running < 0 || value.Healthy < 0 || value.Failed < 0 || value.Cancelled < 0 || value.Superseded < 0 ||
		value.Pending+value.Running+value.Healthy+value.Failed+value.Cancelled+value.Superseded != value.Total {
		return false
	}
	if value.State != challengepublication.StateQueued && value.State != challengepublication.StateRunning &&
		value.State != challengepublication.StateHealthy && value.State != challengepublication.StateFailed &&
		value.State != challengepublication.StateActive {
		return false
	}
	if value.State == challengepublication.StateActive {
		return value.Reason == "-" && value.ConfigPublication != nil &&
			value.ConfigPublication.PublicationID != uuid.Nil && value.ConfigPublication.Revision > 0
	}
	return value.ConfigPublication == nil && (value.Reason == "-" || value.Reason == "" ||
		value.Reason == challengepublication.ReasonWaitingForNodes ||
		value.Reason == challengepublication.ReasonNodeApplyFailed ||
		value.Reason == challengepublication.ReasonExternalAdapterMissing ||
		value.Reason == challengepublication.ReasonConfigurationPublishFail)
}

func classifyPublicationRoute(request *http.Request) publicationRoute {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || path.Clean(request.URL.Path) != request.URL.Path {
		return 0
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 6 || segments[0] != "v1" || segments[1] != "tenant-scopes" || segments[2] == "" ||
		segments[3] != "challenge-policies" || segments[4] == "" || segments[5] != "publications" {
		return 0
	}
	switch len(segments) {
	case 6:
		return publicationCollectionRoute
	case 7:
		if segments[6] != "" {
			return publicationStatusRoute
		}
	case 8:
		if segments[6] != "" && segments[7] == "promote" {
			return publicationPromoteRoute
		}
	}
	return 0
}
