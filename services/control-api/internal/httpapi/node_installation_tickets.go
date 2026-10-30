package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/installationban"
	"github.com/google/uuid"
)

// NodeTicketReader reads each node's last reported ServiceTicket (PF09:
// the node page shows the last ticket time and the days left).
type NodeTicketReader interface {
	NodeTickets(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID, now time.Time) ([]installationban.NodeTicket, error)
}

type nodeInstallationTicketsResponse struct {
	ObservedAt time.Time                    `json:"observed_at"`
	Items      []installationban.NodeTicket `json:"items"`
}

// handleGetNodeInstallationTickets: GET /v1/nodes/installation-tickets?node_id=…
// (1–300 distinct canonical UUIDs, nodes.read).
func (s *Server) handleGetNodeInstallationTickets(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	ids, err := nodeInstallationTicketsQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node installation ticket query")
		return
	}
	if s.nodeTickets == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_tickets_unavailable", "node installation tickets are unavailable")
		return
	}
	now := time.Now().UTC()
	items, err := s.nodeTickets.NodeTickets(r.Context(), principal.ScopeID, ids, now)
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_tickets_unavailable", "node installation tickets are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, nodeInstallationTicketsResponse{ObservedAt: now, Items: items})
}

func nodeInstallationTicketsQuery(r *http.Request) ([]uuid.UUID, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	values := query["node_id"]
	if err != nil || len(query) != 1 || len(values) < 1 || len(values) > installationban.MaxNodeTicketBatch {
		return nil, errors.New("invalid node ticket query")
	}
	ids := make([]uuid.UUID, 0, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, raw := range values {
		id, err := uuid.Parse(raw)
		if _, duplicate := seen[id]; err != nil || id == uuid.Nil || id.String() != raw || duplicate {
			return nil, errors.New("invalid node identifier")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}
