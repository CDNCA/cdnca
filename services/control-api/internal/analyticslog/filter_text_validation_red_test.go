package analyticslog

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceRejectsInvalidFilterTextBeforeStore(t *testing.T) {
	from := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	base := Filter{From: from, To: from.Add(time.Hour)}
	actor := Actor{
		ScopeKind:   "tenant",
		TenantID:    "10000000-0000-4000-8000-00000000000a",
		Permissions: []string{ReadPermission},
	}

	tests := map[string]func(*Filter){
		"carrier C1 control": func(filter *Filter) { filter.Carrier = "carrier-\u0080" },
		"JA4 C1 control":     func(filter *Filter) { filter.JA4 = "ja4-\u009f" },
		"URI invalid UTF-8":  func(filter *Filter) { filter.URIPath = string([]byte{'/', 'a', 0x80}) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := &filterTextRecordingStore{}
			service, err := NewService(store)
			if err != nil {
				t.Fatal(err)
			}
			filter := base
			mutate(&filter)
			_, err = service.ListAccess(context.Background(), actor, QueryRequest{
				Audience: AudienceTenant,
				Filter:   filter,
				Limit:    1,
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if store.accessCalls != 0 {
				t.Fatalf("store access calls = %d, want 0", store.accessCalls)
			}
		})
	}
}

func TestServiceAcceptsLegalUnicodeFilterText(t *testing.T) {
	from := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	store := &filterTextRecordingStore{}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ListAccess(context.Background(), Actor{
		ScopeKind:   "tenant",
		TenantID:    "10000000-0000-4000-8000-00000000000a",
		Permissions: []string{ReadPermission},
	}, QueryRequest{
		Audience: AudienceTenant,
		Filter: Filter{
			From: from, To: from.Add(time.Hour),
			Carrier: "\u4e2d\u56fd\u79fb\u52a8", JA4: "\u5408\u6cd5\u6307\u7eb9", URIPath: "/\u8d44\u6e90",
		},
		Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.accessCalls != 1 {
		t.Fatalf("store access calls = %d, want 1", store.accessCalls)
	}
}

type filterTextRecordingStore struct {
	accessCalls int
}

func (store *filterTextRecordingStore) ListAccess(context.Context, scope, Filter, uint16, string) (AccessPage, error) {
	store.accessCalls++
	return AccessPage{}, nil
}

func (*filterTextRecordingStore) ListBlockEvents(context.Context, scope, Filter, uint16, string) (BlockEventPage, error) {
	return BlockEventPage{}, nil
}
