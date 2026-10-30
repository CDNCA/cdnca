package announcement

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func assertAnnouncementField(t *testing.T, err, sentinel error, field, reason string) {
	t.Helper()
	located, ok := fielderr.As(err)
	if !errors.Is(err, sentinel) || !ok || located.Field != field || located.Reason != reason {
		t.Fatalf("error = %v, want %v at %s/%s", err, sentinel, field, reason)
	}
}

// fix-fielderr-be4: a refused announcement draft names its body field (the
// JSON name the editor sends) and keeps the package's sentinel.
func TestDraftRefusalsLocateField(t *testing.T) {
	content := Content{Title: "维护通知", Body: "今晚维护"}
	presentation := Presentation{Format: FormatContent, SortOrder: 1, Visible: true}
	audience := Audience{All: true}
	for name, check := range map[string]struct {
		content       Content
		presentation  Presentation
		audience      Audience
		visibility    string
		sentinel      error
		field, reason string
	}{
		"title empty":   {Content{Body: "b"}, presentation, audience, VisibilityRetain, ErrInvalidContent, "title", fielderr.Required},
		"title long":    {Content{Title: strings.Repeat("标", MaxTitleRunes+1), Body: "b"}, presentation, audience, VisibilityRetain, ErrInvalidContent, "title", fielderr.TooLong},
		"title control": {Content{Title: "a​b", Body: "b"}, presentation, audience, VisibilityRetain, ErrInvalidContent, "title", fielderr.Invalid},
		"body empty":    {Content{Title: "t"}, presentation, audience, VisibilityRetain, ErrInvalidContent, "body", fielderr.Required},
		"body long":     {Content{Title: "t", Body: strings.Repeat("a", MaxBodyBytes+1)}, presentation, audience, VisibilityRetain, ErrInvalidContent, "body", fielderr.TooLong},
		"body link":     {Content{Title: "t", Body: "见 https://example.test"}, presentation, audience, VisibilityRetain, ErrInvalidContent, "body", fielderr.Invalid},
		"sort":          {content, Presentation{Format: FormatContent, SortOrder: 1_000_000}, audience, VisibilityRetain, ErrInvalidInput, "sort_order", fielderr.OutOfRange},
		"format":        {content, Presentation{Format: "video", SortOrder: 1}, audience, VisibilityRetain, ErrInvalidInput, "format", fielderr.Invalid},
		"link missing":  {Content{Title: "t"}, Presentation{Format: FormatLink, SortOrder: 1}, audience, VisibilityRetain, ErrInvalidInput, "link_url", fielderr.Required},
		"link scheme":   {Content{Title: "t"}, Presentation{Format: FormatLink, SortOrder: 1, LinkURL: "ftp://example.test"}, audience, VisibilityRetain, ErrInvalidInput, "link_url", fielderr.Invalid},
		"all and users": {content, presentation, Audience{All: true, UserIDs: []uuid.UUID{uuid.New()}}, VisibilityRetain, ErrInvalidAudience, "all", fielderr.Invalid},
		"no targets":    {content, presentation, Audience{}, VisibilityRetain, ErrInvalidAudience, "user_ids", fielderr.Required},
		"nil group":     {content, presentation, Audience{GroupIDs: []uuid.UUID{uuid.Nil}}, VisibilityRetain, ErrInvalidAudience, "group_ids", fielderr.Invalid},
		"visibility":    {content, presentation, audience, "forever", ErrInvalidInput, "withdrawal_visibility", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateDraftInput(check.content, check.presentation, check.audience, check.visibility, "key-1", "request-1")
			assertAnnouncementField(t, err, check.sentinel, check.field, check.reason)
		})
	}
	if err := validateDraftInput(content, presentation, audience, VisibilityRetain, "", "request-1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad key: %v", err)
	} else if _, ok := fielderr.As(err); ok {
		t.Fatalf("bad key located: %v", err)
	}
}

func TestGlobalDraftRefusalsLocateField(t *testing.T) {
	content := Content{Title: "维护通知", Body: "今晚维护"}
	presentation := Presentation{Format: FormatContent, SortOrder: 1, Visible: true}
	for name, check := range map[string]struct {
		content       Content
		presentation  Presentation
		audience      GlobalAudience
		sentinel      error
		field, reason string
	}{
		"title":       {Content{Body: "b"}, presentation, GlobalAudience{AllTenants: true}, ErrInvalidContent, "title", fielderr.Required},
		"body":        {Content{Title: "t", Body: " "}, presentation, GlobalAudience{AllTenants: true}, ErrInvalidContent, "body", fielderr.Required},
		"sort":        {content, Presentation{Format: FormatContent, SortOrder: -1}, GlobalAudience{AllTenants: true}, ErrInvalidContent, "sort_order", fielderr.OutOfRange},
		"all and ids": {content, presentation, GlobalAudience{AllTenants: true, TenantScopeIDs: []uuid.UUID{uuid.New()}}, ErrInvalidAudience, "all_tenants", fielderr.Invalid},
		"none":        {content, presentation, GlobalAudience{}, ErrInvalidAudience, "tenant_scope_ids", fielderr.Required},
		"nil role":    {content, presentation, GlobalAudience{RoleTargets: []GlobalRoleTarget{{ScopeID: uuid.New()}}}, ErrInvalidAudience, "role_targets", fielderr.Invalid},
		"nil user":    {content, presentation, GlobalAudience{UserTargets: []GlobalUserTarget{{UserID: uuid.New()}}}, ErrInvalidAudience, "user_targets", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateGlobalDraftInput(check.content, check.presentation, check.audience, VisibilityRetain, "key-1", "request-1")
			assertAnnouncementField(t, err, check.sentinel, check.field, check.reason)
		})
	}
	err := validateGlobalDraftInput(content, presentation, GlobalAudience{AllTenants: true}, "forever", "key-1", "request-1")
	assertAnnouncementField(t, err, ErrInvalidInput, "withdrawal_visibility", fielderr.Invalid)
}
