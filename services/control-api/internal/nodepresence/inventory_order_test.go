package nodepresence

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
)

func TestInventoryOrderCursor(t *testing.T) {
	request := InventoryListRequest{ScopeID: uuid.New(), Order: InventoryManagementSortDesc, State: "active", Presence: "unknown", Search: "界<&", Limit: 2}
	item := InventoryItem{Node: node.Node{ID: uuid.New(), DisplayID: "9223372036854775807", ManagementSettings: node.NodeManagementSettings{Sort: 999999}}}
	cursor, err := encodeInventoryOrderCursor(request, item)
	if err != nil {
		t.Fatal(err)
	}
	request.OrderedAfter = cursor
	position, err := validateInventoryOrder(request)
	if err != nil || position.LastID != item.ID || position.LastDisplayID != item.DisplayID || position.LastSort != 999999 {
		t.Fatalf("cursor round trip: %+v %v", position, err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cursor, "nso1."))
	invalid := []string{"", "nso1.", cursor + "=", cursor + "\n", cursor[:10] + "\r\n" + cursor[10:], strings.Repeat("x", 2049), "nso1.__8"}
	for _, change := range []func(*inventoryOrderCursor){
		func(c *inventoryOrderCursor) { c.Version = 2 }, func(c *inventoryOrderCursor) { c.ScopeID = uuid.New() },
		func(c *inventoryOrderCursor) { c.Order = "uuid_asc" }, func(c *inventoryOrderCursor) { c.State = "" },
		func(c *inventoryOrderCursor) { c.Presence = "" }, func(c *inventoryOrderCursor) { c.Search = "" },
		func(c *inventoryOrderCursor) { c.LastID = uuid.Nil }, func(c *inventoryOrderCursor) { c.LastSort = -1 },
		func(c *inventoryOrderCursor) { c.LastSort = 1000000 }, func(c *inventoryOrderCursor) { c.LastDisplayID = "0" },
		func(c *inventoryOrderCursor) { c.LastDisplayID = "01" }, func(c *inventoryOrderCursor) { c.LastDisplayID = "+1" },
		func(c *inventoryOrderCursor) { c.LastDisplayID = "9223372036854775808" },
	} {
		copy := *position
		change(&copy)
		data, _ := json.Marshal(copy)
		invalid = append(invalid, "nso1."+base64.RawURLEncoding.EncodeToString(data))
	}
	for _, data := range []string{string(raw) + " ", strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"extra":true`, 1), strings.Replace(string(raw), `"version":1,`, "", 1)} {
		invalid = append(invalid, "nso1."+base64.RawURLEncoding.EncodeToString([]byte(data)))
	}
	for index, cursor := range invalid {
		request.OrderedAfter = cursor
		if _, err := decodeInventoryOrderCursor(request); !errors.Is(err, node.ErrInvalidInput) {
			t.Fatalf("invalid cursor %d: %v", index, err)
		}
	}
	request.OrderedAfter, request.Order = cursor, ""
	if _, err := validateInventoryOrder(request); !errors.Is(err, node.ErrInvalidInput) {
		t.Fatal("legacy mode accepted sorted cursor")
	}
	request.Order, request.After = InventoryManagementSortDesc, &item.ID
	if _, err := validateInventoryOrder(request); !errors.Is(err, node.ErrInvalidInput) {
		t.Fatal("sorted mode accepted UUID position")
	}
	request.After, request.OrderedAfter, request.Order = nil, "", "management_sort_asc"
	if _, err := validateInventoryOrder(request); !errors.Is(err, node.ErrInvalidInput) {
		t.Fatal("unknown order accepted")
	}
	request.Order = ""
	if cursor, err := validateInventoryOrder(request); err != nil || cursor != nil {
		t.Fatal("legacy empty cursor rejected")
	}
}
