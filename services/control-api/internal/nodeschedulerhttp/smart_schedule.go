package nodeschedulerhttp

import (
	"context"
	"net/http"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// smartScheduleService is optional so test doubles of Service need not
// implement it (migration 609).
type smartScheduleService interface {
	GetSmartSchedule(context.Context, nodescheduler.Actor, uuid.UUID, nodescheduler.SmartScheduleReader) (nodescheduler.SmartSchedule, error)
	PutSmartSchedule(context.Context, nodescheduler.Actor, uuid.UUID, nodescheduler.SmartScheduleSettings, string, string) (nodescheduler.SmartScheduleSettings, int64, error)
	LatencyMatrix(context.Context, nodescheduler.Actor, uuid.UUID, int, nodescheduler.SmartScheduleReader) (any, error)
}

type smartScheduleBody struct {
	Enabled              *bool   `json:"enabled"`
	TopN                 *int    `json:"top_n"`
	Granularity          *string `json:"granularity"`
	LatencyWindowMinutes *int    `json:"latency_window_minutes"`
	MaxLoadPercent       *int    `json:"max_load_percent"`
}

// WithSmartSchedule enables the smart schedule routes with reader.
func (handler *Handler) WithSmartSchedule(reader nodescheduler.SmartScheduleReader) *Handler {
	handler.smartReader = reader
	return handler
}

func (handler *Handler) smartService(response http.ResponseWriter, request *http.Request) (smartScheduleService, bool) {
	service, ok := handler.service.(smartScheduleService)
	if !ok || handler.smartReader == nil {
		handler.writeError(response, request, ErrInvalidHandlerConfig)
		return nil, false
	}
	return service, true
}

func (handler *Handler) smartSchedule(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPut {
		handler.methodNotAllowed(response, request, "GET, PUT")
		return
	}
	service, ok := handler.smartService(response, request)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	actor, ok := handler.actor(response, request, request.Method == http.MethodPut)
	if !ok {
		return
	}
	if request.Method == http.MethodPut {
		key, requestID, ok := handler.metadataWithoutRevision(response, request)
		if !ok {
			return
		}
		var body smartScheduleBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.Enabled == nil || body.TopN == nil || body.Granularity == nil || body.LatencyWindowMinutes == nil ||
			body.MaxLoadPercent == nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		if _, _, err := service.PutSmartSchedule(request.Context(), actor, groupID, nodescheduler.SmartScheduleSettings{
			Enabled: *body.Enabled, TopN: *body.TopN, Granularity: *body.Granularity,
			LatencyWindowMinutes: *body.LatencyWindowMinutes, MaxLoadPercent: *body.MaxLoadPercent,
		}, key, requestID); err != nil {
			handler.writeError(response, request, err)
			return
		}
	}
	view, err := service.GetSmartSchedule(request.Context(), actor, groupID, handler.smartReader)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(view.Revision))
	handler.writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) latencyMatrix(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	service, ok := handler.smartService(response, request)
	if !ok {
		return
	}
	groupID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	window := 15
	if values := request.URL.Query()["window"]; len(values) > 0 {
		parsed, err := strconv.Atoi(values[0])
		if len(values) > 1 || err != nil || parsed < 1 || parsed > 60 {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		window = parsed
	}
	actor, ok := handler.actor(response, request, false)
	if !ok {
		return
	}
	matrix, err := service.LatencyMatrix(request.Context(), actor, groupID, window, handler.smartReader)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeJSON(response, http.StatusOK, matrix)
}
