package l4forward

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestListRejectsInvalidOwnerAndPublicationFiltersBeforeStore(t *testing.T) {
	actor := Actor{ScopeID: uuid.New(), UserID: uuid.New(), ScopeKind: "tenant"}
	zero, negative := int64(0), int64(-1)
	for _, filter := range []ListFilter{
		{OwnerDisplayID: &zero}, {OwnerDisplayID: &negative},
		{PublicationState: "retry_wait"}, {PublicationState: " normal "}, {PublicationState: "succeeded "},
	} {
		filter.Page, filter.Limit = 1, 20
		if _, err := NewService(nil).List(t.Context(), actor, filter); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("filter=%+v err=%v", filter, err)
		}
	}
}
