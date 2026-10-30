package sitegroup

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// fix-fielderr-be4: a refused name/remark names the field (details.field) so
// the site group form marks it. The checks run before the database.
func TestWriteRefusalsLocateField(t *testing.T) {
	service := &Service{}
	metadata := WriteMetadata{IdempotencyKey: "key-1", RequestID: "request-1"}
	long, control := strings.Repeat("备", 1025), "a\u0000b"
	scope := uuid.New()
	for name, check := range map[string]struct {
		run           func() error
		field, reason string
	}{
		"create empty name": {func() error {
			_, err := service.Create(t.Context(), Actor{}, CreateRequest{TargetScopeID: scope, Name: " ", WriteMetadata: metadata})
			return err
		}, "name", fielderr.Required},
		"create long name": {func() error {
			_, err := service.Create(t.Context(), Actor{}, CreateRequest{TargetScopeID: scope, Name: strings.Repeat("界", 129), WriteMetadata: metadata})
			return err
		}, "name", fielderr.TooLong},
		"create control name": {func() error {
			_, err := service.Create(t.Context(), Actor{}, CreateRequest{TargetScopeID: scope, Name: "a\u0085b", WriteMetadata: metadata})
			return err
		}, "name", fielderr.Invalid},
		"create long remark": {func() error {
			_, err := service.Create(t.Context(), Actor{}, CreateRequest{TargetScopeID: scope, Name: "g", Remark: &long, WriteMetadata: metadata})
			return err
		}, "remark", fielderr.TooLong},
		"rename control remark": {func() error {
			_, err := service.Rename(t.Context(), Actor{}, RenameRequest{TargetScopeID: scope, ID: uuid.New(), ExpectedRevision: 1, Name: "g", Remark: &control, WriteMetadata: metadata})
			return err
		}, "remark", fielderr.Invalid},
		"rename empty name": {func() error {
			_, err := service.Rename(t.Context(), Actor{}, RenameRequest{TargetScopeID: scope, ID: uuid.New(), ExpectedRevision: 1, Name: "", WriteMetadata: metadata})
			return err
		}, "name", fielderr.Required},
	} {
		t.Run(name, func(t *testing.T) {
			err := check.run()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
			}
			located, ok := fielderr.As(err)
			if !ok || located.Field != check.field || located.Reason != check.reason {
				t.Fatalf("field error = %+v (located %v), want %s/%s", located, ok, check.field, check.reason)
			}
		})
	}
	// Bad write metadata is not a form field.
	_, err := service.Create(t.Context(), Actor{}, CreateRequest{TargetScopeID: scope, Name: "g", WriteMetadata: WriteMetadata{}})
	if _, ok := fielderr.As(err); !errors.Is(err, ErrInvalidInput) || ok {
		t.Fatalf("bad metadata error = %v", err)
	}
}
