package errorpagecontrol

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type SlotHTTPDomain interface {
	ListSlots(context.Context, Actor) (SlotPage, error)
	GetSlot(context.Context, Actor, string) (SlotDocument, error)
	BindSlot(context.Context, Actor, BindSlotRequest) (WriteResult[SlotBinding], error)
	UnbindSlot(context.Context, Actor, UnbindSlotRequest) (WriteResult[SlotBinding], error)
}

type bindSlotBody struct {
	AssetID uuid.UUID `json:"asset_id"`
}

func (handler *Handler) handleSlots(response http.ResponseWriter, request *http.Request, actor Actor) {
	if request.Method != http.MethodGet || !onlyQuery(request.URL.Query()) || !emptyBody(request) {
		writeMethodOrInput(response, request.Method == http.MethodGet)
		return
	}
	domain, ok := handler.domain.(SlotHTTPDomain)
	if !ok {
		writeHTTPError(response, ErrUnavailable)
		return
	}
	result, err := domain.ListSlots(request.Context(), actor)
	writeDomainResponse(response, http.StatusOK, result, err)
}

func (handler *Handler) handleSlotResource(response http.ResponseWriter, request *http.Request, actor Actor, suffix string) {
	if strings.Contains(suffix, "/") || !validSlotKey(suffix) {
		writeHTTPError(response, ErrNotFound)
		return
	}
	domain, ok := handler.domain.(SlotHTTPDomain)
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
		result, err := domain.GetSlot(request.Context(), actor, suffix)
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodPut:
		if !onlyQuery(request.URL.Query()) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		var body bindSlotBody
		if err := decodeJSONBody(request, &body); err != nil || body.AssetID == uuid.Nil {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		revision, err := expectedSlotRevision(request.Header.Get("If-Match"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := domain.BindSlot(request.Context(), actor, BindSlotRequest{
			Key: suffix, AssetID: body.AssetID, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusOK, result, err)
	case http.MethodDelete:
		if !onlyQuery(request.URL.Query()) || !emptyBody(request) {
			writeHTTPError(response, ErrInvalidInput)
			return
		}
		revision, err := expectedSlotRevision(request.Header.Get("If-Match"))
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		metadata, err := writeMetadataFromHeaders(request)
		if err != nil {
			writeHTTPError(response, err)
			return
		}
		result, err := domain.UnbindSlot(request.Context(), actor, UnbindSlotRequest{
			Key: suffix, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		writeDomainResponse(response, http.StatusOK, result, err)
	default:
		writeHTTPError(response, errMethodNotAllowed)
	}
}

func expectedSlotRevision(value string) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, ErrInvalidInput
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 0 || strconv.FormatInt(revision, 10) != value[1:len(value)-1] {
		return 0, ErrInvalidInput
	}
	return revision, nil
}
