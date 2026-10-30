package notificationhttp

import (
	"context"
	"net/http"
	"net/url"

	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
)

type DeliveryHistoryService interface {
	ListDeliveryHistory(context.Context, notificationcontrol.Actor, notificationcontrol.DeliveryHistoryQuery) (notificationcontrol.DeliveryHistoryPage, error)
}

func (h *Handler) listDeliveryHistory(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.actor(w, r)
	if !ok {
		return
	}
	service, ok := h.service.(DeliveryHistoryService)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	value, err := service.ListDeliveryHistory(r.Context(), actor, deliveryHistoryQuery(r))
	h.writeValue(w, r, value, err, -1)
}

func deliveryHistoryQuery(r *http.Request) notificationcontrol.DeliveryHistoryQuery {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return notificationcontrol.DeliveryHistoryQuery{Invalid: true}
	}
	allowed := map[string]bool{
		"scope_id": true, "channel": true, "state": true, "result": true, "event_type": true, "user_id": true,
		"message_id": true, "from": true, "to": true, "limit": true, "cursor": true,
	}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			return notificationcontrol.DeliveryHistoryQuery{Invalid: true}
		}
	}
	return notificationcontrol.DeliveryHistoryQuery{
		ScopeID: values.Get("scope_id"), Channel: values.Get("channel"), State: values.Get("state"),
		EventType: values.Get("event_type"), UserID: values.Get("user_id"), MessageID: values.Get("message_id"), Result: values.Get("result"),
		From: values.Get("from"), To: values.Get("to"), Limit: values.Get("limit"), Cursor: values.Get("cursor"),
	}
}
