package nodeschedulerhttp

import (
	"context"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type l2ConfigBody struct {
	Name       string  `json:"name"`
	Region     *string `json:"region"`
	Remark     string  `json:"remark"`
	Mode       string  `json:"mode"`
	LoadMethod string  `json:"load_method"`
}

type l2ConditionBody struct {
	Name   string                 `json:"name"`
	Remark string                 `json:"remark"`
	Rules  []nodescheduler.L2Rule `json:"rules"`
}

type l2NodeAddBody struct {
	ConfigID    uuid.UUID   `json:"config_id"`
	NodeIDs     []uuid.UUID `json:"node_ids"`
	ConditionID *uuid.UUID  `json:"condition_id"`
}

type l2NodeWriteBody struct {
	ConditionID *uuid.UUID `json:"condition_id"`
	Enabled     *bool      `json:"enabled"`
	Weight      *int       `json:"weight"`
	Sort        *int       `json:"sort"`
}

func (handler *Handler) l2ConfigCollection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		items, err := handler.service.ListL2Configs(request.Context(), actor)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, true)
		if !ok {
			return
		}
		var body l2ConfigBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.Region == nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.PutL2Config(request.Context(), actor, nodescheduler.L2ConfigWriteRequest{
			ExpectedRevision: revision, Name: body.Name, Region: *body.Region, Remark: body.Remark,
			Mode: body.Mode, LoadMethod: body.LoadMethod, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Config.Revision))
		response.Header().Set("Location", "/v1/l2-configs/"+result.Config.ID.String())
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusCreated, result.Config)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) l2ConfigItem(response http.ResponseWriter, request *http.Request) {
	configID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		item, err := handler.service.GetL2Config(request.Context(), actor, configID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(item.Revision))
		handler.writeJSON(response, http.StatusOK, item)
	case http.MethodPut:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		var body l2ConfigBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.Region == nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.PutL2Config(request.Context(), actor, nodescheduler.L2ConfigWriteRequest{
			ConfigID: configID, ExpectedRevision: revision, Name: body.Name, Region: *body.Region, Remark: body.Remark,
			Mode: body.Mode, LoadMethod: body.LoadMethod, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Config.Revision))
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusOK, result.Config)
	case http.MethodDelete:
		handler.deleteL2(response, request, configID, handler.service.DeleteL2Config)
	default:
		handler.methodNotAllowed(response, request, "GET, PUT, DELETE")
	}
}

func (handler *Handler) l2ConditionCollection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		items, err := handler.service.ListL2Conditions(request.Context(), actor)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, true)
		if !ok {
			return
		}
		var body l2ConditionBody
		if !handler.decode(response, request, &body) {
			return
		}
		result, err := handler.service.PutL2Condition(request.Context(), actor, nodescheduler.L2ConditionWriteRequest{
			ExpectedRevision: revision, Name: body.Name, Remark: body.Remark, Rules: body.Rules,
			IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Condition.Revision))
		response.Header().Set("Location", "/v1/l2-conds/"+result.Condition.ID.String())
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusCreated, result.Condition)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) l2ConditionItem(response http.ResponseWriter, request *http.Request) {
	conditionID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPut:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		var body l2ConditionBody
		if !handler.decode(response, request, &body) {
			return
		}
		result, err := handler.service.PutL2Condition(request.Context(), actor, nodescheduler.L2ConditionWriteRequest{
			ConditionID: conditionID, ExpectedRevision: revision, Name: body.Name, Remark: body.Remark,
			Rules: body.Rules, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Condition.Revision))
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusOK, result.Condition)
	case http.MethodDelete:
		handler.deleteL2(response, request, conditionID, handler.service.DeleteL2Condition)
	default:
		handler.methodNotAllowed(response, request, "PUT, DELETE")
	}
}

func (handler *Handler) l2NodeCollection(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		actor, ok := handler.actor(response, request, false)
		if !ok {
			return
		}
		query := request.URL.Query()
		if len(query["config_id"]) != 1 || len(query["available"]) > 1 {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		configID, err := uuid.Parse(query.Get("config_id"))
		if err != nil || configID == uuid.Nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		if available := query.Get("available"); available != "" && available != "true" {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		} else if available == "true" {
			items, err := handler.service.ListAvailableL2Nodes(request.Context(), actor, configID)
			if err != nil {
				handler.writeError(response, request, err)
				return
			}
			handler.writeJSON(response, http.StatusOK, map[string]any{"items": items})
			return
		}
		items, err := handler.service.ListL2Nodes(request.Context(), actor, configID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, true)
		if !ok {
			return
		}
		var body l2NodeAddBody
		if !handler.decode(response, request, &body) {
			return
		}
		result, err := handler.service.AddL2Nodes(request.Context(), actor, nodescheduler.L2NodeAddRequest{
			ConfigID: body.ConfigID, NodeIDs: body.NodeIDs, ConditionID: body.ConditionID,
			ExpectedRevision: revision, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusCreated, map[string]any{"items": result.Items})
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) l2NodeItem(response http.ResponseWriter, request *http.Request) {
	membershipID, ok := handler.pathUUID(response, request, "id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPut:
		actor, ok := handler.actor(response, request, true)
		if !ok {
			return
		}
		revision, key, requestID, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		var body l2NodeWriteBody
		if !handler.decode(response, request, &body) {
			return
		}
		if body.Enabled == nil || body.Weight == nil || body.Sort == nil {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.PutL2Node(request.Context(), actor, nodescheduler.L2NodeWriteRequest{
			MembershipID: membershipID, ConditionID: body.ConditionID, ExpectedRevision: revision,
			Enabled: *body.Enabled, Weight: *body.Weight, Sort: *body.Sort, IdempotencyKey: key, RequestID: requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Node.Revision))
		setReplay(response, result.Replayed)
		handler.writeJSON(response, http.StatusOK, result.Node)
	case http.MethodDelete:
		handler.deleteL2(response, request, membershipID, handler.service.DeleteL2Node)
	default:
		handler.methodNotAllowed(response, request, "PUT, DELETE")
	}
}

func (handler *Handler) deleteL2(
	response http.ResponseWriter,
	request *http.Request,
	id uuid.UUID,
	remove func(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error),
) {
	actor, ok := handler.actor(response, request, true)
	if !ok {
		return
	}
	revision, key, requestID, ok := handler.writeMetadata(response, request, false)
	if !ok {
		return
	}
	result, err := remove(request.Context(), actor, id, revision, key, requestID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Revision))
	setReplay(response, result.Replayed)
	response.WriteHeader(http.StatusNoContent)
}
