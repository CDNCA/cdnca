package nodepresence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
)

const InventoryManagementSortDesc = "management_sort_desc"

// A cursor is an untrusted keyset bookmark, never an authorization credential.
// Scope and filters must match the freshly authorized request on every read.
type inventoryOrderCursor struct {
	Version       int       `json:"version"`
	ScopeID       uuid.UUID `json:"scope_id"`
	Order         string    `json:"order"`
	State         string    `json:"status"`
	Presence      string    `json:"presence"`
	Search        string    `json:"search"`
	LastSort      int       `json:"last_sort"`
	LastDisplayID string    `json:"last_display_id"`
	LastID        uuid.UUID `json:"last_id"`
}

func validateInventoryOrder(request InventoryListRequest) (*inventoryOrderCursor, error) {
	if request.Order == "" {
		if request.OrderedAfter != "" {
			return nil, node.ErrInvalidInput
		}
		return nil, nil
	}
	if request.Order != InventoryManagementSortDesc || request.After != nil {
		return nil, node.ErrInvalidInput
	}
	if request.OrderedAfter == "" {
		return nil, nil
	}
	return decodeInventoryOrderCursor(request)
}

func decodeInventoryOrderCursor(request InventoryListRequest) (*inventoryOrderCursor, error) {
	raw := request.OrderedAfter
	if len(raw) > 2048 || !strings.HasPrefix(raw, "nso1.") {
		return nil, node.ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(raw, "nso1."))
	if err != nil || "nso1."+base64.RawURLEncoding.EncodeToString(data) != raw {
		return nil, node.ErrInvalidInput
	}
	var cursor inventoryOrderCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, node.ErrInvalidInput
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, node.ErrInvalidInput
	}
	displayID, err := strconv.ParseInt(cursor.LastDisplayID, 10, 64)
	if err != nil || displayID <= 0 || strconv.FormatInt(displayID, 10) != cursor.LastDisplayID ||
		cursor.Version != 1 || cursor.ScopeID != request.ScopeID || cursor.Order != request.Order ||
		cursor.State != request.State || cursor.Presence != request.Presence || cursor.Search != request.Search ||
		cursor.LastSort < 0 || cursor.LastSort > 999999 || cursor.LastID == uuid.Nil {
		return nil, node.ErrInvalidInput
	}
	return &cursor, nil
}

func encodeInventoryOrderCursor(request InventoryListRequest, item InventoryItem) (string, error) {
	cursor := inventoryOrderCursor{Version: 1, ScopeID: request.ScopeID, Order: request.Order,
		State: request.State, Presence: request.Presence, Search: request.Search,
		LastSort: item.ManagementSettings.Sort, LastDisplayID: item.DisplayID, LastID: item.ID}
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	encoded := "nso1." + base64.RawURLEncoding.EncodeToString(data)
	request.OrderedAfter = encoded
	if _, err := decodeInventoryOrderCursor(request); err != nil {
		return "", err
	}
	return encoded, nil
}
