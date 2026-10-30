package nodepresence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
)

func TestInventoryListRejectsInvalidSearch(t *testing.T) {
	tests := map[string]string{
		"surrounding whitespace": " padded ",
		"control character":      "line\nbreak",
		"line separator":         "line\u2028break",
		"invalid UTF-8":          string([]byte{0xff}),
		"too long":               strings.Repeat("界", MaxInventorySearchRunes+1),
	}
	for name, search := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (&Inventory{}).List(context.Background(), InventoryListRequest{
				ScopeID: uuid.New(),
				Search:  search,
				Limit:   1,
			})
			if !errors.Is(err, node.ErrInvalidInput) {
				t.Fatalf("List() error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
