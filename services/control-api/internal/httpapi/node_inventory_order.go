package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
)

func parseNodeInventoryOrder(rawQuery string, scopeID uuid.UUID) (nodepresence.InventoryListRequest, error) {
	request := nodepresence.InventoryListRequest{ScopeID: scopeID, Limit: 20}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return request, node.ErrInvalidInput
	}
	for key, values := range query {
		if len(values) != 1 {
			return request, node.ErrInvalidInput
		}
		switch key {
		case "order", "status", "presence", "search", "limit", "cursor":
		default:
			return request, node.ErrInvalidInput
		}
	}
	request.Order = query.Get("order")
	if request.Order != nodepresence.InventoryManagementSortDesc {
		return request, node.ErrInvalidInput
	}
	if query.Has("limit") {
		request.Limit, err = strconv.Atoi(query.Get("limit"))
		if err != nil || strconv.Itoa(request.Limit) != query.Get("limit") {
			return request, node.ErrInvalidInput
		}
	}
	request.State, request.Presence = query.Get("status"), query.Get("presence")
	search := query.Get("search")
	if !utf8.ValidString(search) || utf8.RuneCountInString(search) > nodepresence.MaxInventorySearchRunes || strings.ContainsFunc(search, func(character rune) bool {
		return unicode.IsControl(character) || character == '\u2028' || character == '\u2029'
	}) {
		return request, node.ErrInvalidInput
	}
	request.Search = strings.TrimSpace(search)
	request.OrderedAfter = query.Get("cursor")
	if query.Has("cursor") && request.OrderedAfter == "" {
		return request, node.ErrInvalidInput
	}
	return request, nil
}

func (s *Server) handleListNodesOrdered(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	request, err := parseNodeInventoryOrder(r.URL.RawQuery, principal.ScopeID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node inventory order query is invalid")
		return
	}
	result, err := s.nodeInventory.List(r.Context(), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Order      string                       `json:"order"`
		Items      []nodepresence.InventoryItem `json:"items"`
		NextCursor string                       `json:"next_cursor,omitempty"`
	}{Order: request.Order, Items: result.Items, NextCursor: result.NextOrderedCursor})
}
