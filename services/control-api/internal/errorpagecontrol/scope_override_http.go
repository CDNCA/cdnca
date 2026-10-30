package errorpagecontrol

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type ScopeOverrideHTTPDomain interface {
	ListScopeOverrides(context.Context, Actor) (ScopeOverridePage, error)
	GetScopeOverride(context.Context, Actor, int64) (ScopeOverride, error)
	CreateScopeOverride(context.Context, Actor, CreateScopeOverrideRequest) (WriteResult[ScopeOverride], error)
	UpdateScopeOverride(context.Context, Actor, UpdateScopeOverrideRequest) (WriteResult[ScopeOverride], error)
	DeleteScopeOverride(context.Context, Actor, DeleteScopeOverrideRequest) (WriteResult[ScopeOverride], error)
}

type scopeOverrideTargetBody struct {
	Kind          string `json:"kind"`
	NodeDisplayID string `json:"node_display_id"`
	Region        string `json:"region"`
}

type scopeOverrideItemBody struct {
	Key     string    `json:"key"`
	AssetID uuid.UUID `json:"asset_id"`
}

type createScopeOverrideBody struct {
	Target scopeOverrideTargetBody `json:"target"`
	Items  []scopeOverrideItemBody `json:"items"`
}

type updateScopeOverrideBody struct {
	Items []scopeOverrideItemBody `json:"items"`
}

func (handler *Handler) handleScopeOverrides(response http.ResponseWriter, request *http.Request, actor Actor) {
	domain, ok := handler.domain.(ScopeOverrideHTTPDomain)
	if !ok {
		writeHTTPError(response, ErrUnavailable)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !onlyQuery(request.URL.Query()) || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := domain.ListScopeOverrides(request.Context(), actor)
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodPost:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		var body createScopeOverrideBody
		if err := decodeJSONBody(request, &body); err != nil {
			writeHTTPError(response, err)
			return
		}
		nodeDisplayID, err := optionalPositiveDisplayID(body.Target.NodeDisplayID)
		if err != nil || !validScopeOverrideTarget(body.Target.Kind, nodeDisplayID, body.Target.Region) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		items, err := scopeOverrideBindings(body.Items)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := domain.CreateScopeOverride(request.Context(), actor, CreateScopeOverrideRequest{
			TargetKind: body.Target.Kind, NodeDisplayID: nodeDisplayID, Region: body.Target.Region,
			Items: items, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusCreated, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func (handler *Handler) handleScopeOverrideResource(
	response http.ResponseWriter,
	request *http.Request,
	actor Actor,
	suffix string,
) {
	if strings.Contains(suffix, "/") {
		writeHTTPError(response, ErrNotFound)
		return
	}
	displayID, err := positiveDisplayID(suffix)
	if err != nil {
		writeHTTPError(response, ErrNotFound)
		return
	}
	domain, ok := handler.domain.(ScopeOverrideHTTPDomain)
	if !ok {
		writeHTTPError(response, ErrUnavailable)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if !onlyQuery(request.URL.Query()) || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := domain.GetScopeOverride(request.Context(), actor, displayID)
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodPatch:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		revision, revisionErr := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || revisionErr != nil {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		var body updateScopeOverrideBody
		if err := decodeJSONBody(request, &body); err != nil {
			writeHTTPError(response, err)
			return
		}
		items, err := scopeOverrideBindings(body.Items)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := domain.UpdateScopeOverride(request.Context(), actor, UpdateScopeOverrideRequest{
			DisplayID: displayID, ExpectedRevision: revision, Items: items, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodDelete:
		if !onlyQuery(request.URL.Query()) || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		revision, revisionErr := expectedRevision(request.Header.Get("If-Match"))
		if err != nil || revisionErr != nil {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		result, err := domain.DeleteScopeOverride(request.Context(), actor, DeleteScopeOverrideRequest{
			DisplayID: displayID, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusAccepted, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func scopeOverrideBindings(items []scopeOverrideItemBody) ([]ScopeOverrideBinding, error) {
	bindings := make([]ScopeOverrideBinding, len(items))
	for index, item := range items {
		bindings[index] = ScopeOverrideBinding{Key: item.Key, AssetID: item.AssetID}
	}
	return normalizeScopeOverrideBindings(bindings)
}

func positiveDisplayID(value string) (int64, error) {
	if value == "" || value[0] == '0' {
		return 0, ErrInvalidInput
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 1 || strconv.FormatInt(parsed, 10) != value {
		return 0, ErrInvalidInput
	}
	return parsed, nil
}

func optionalPositiveDisplayID(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	return positiveDisplayID(value)
}
