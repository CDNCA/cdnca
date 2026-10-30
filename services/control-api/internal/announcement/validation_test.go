package announcement

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateContentStrictSafeMarkdown(t *testing.T) {
	t.Parallel()
	valid := Content{
		Title: "计划维护通知",
		Body:  "## 维护窗口\n\n- 开始：02:00\n- 预计：**15 分钟**\n\n`边缘流量不受影响`",
	}
	if err := ValidateContent(valid); err != nil {
		t.Fatalf("valid safe markdown: %v", err)
	}

	cases := []Content{
		{Title: "", Body: "正文"},
		{Title: strings.Repeat("题", MaxTitleRunes+1), Body: "正文"},
		{Title: "标题\n注入", Body: "正文"},
		{Title: "标题", Body: ""},
		{Title: "标题", Body: strings.Repeat("x", MaxBodyBytes+1)},
		{Title: "标题", Body: "正文\x00"},
		{Title: "标题", Body: "<script>alert(1)</script>"},
		{Title: "标题", Body: "![远程图片](https://example.invalid/a.png)"},
		{Title: "标题", Body: "[远程链接](https://example.invalid/)"},
		{Title: "标题", Body: "[伪链接][标签]"},
		{Title: "标题", Body: "协议相对资源 //example.invalid/a"},
		{Title: "标题", Body: "ftp:example.invalid/resource"},
		{Title: "标题", Body: "www.example.invalid/resource"},
		{Title: "标题", Body: "javascript:alert(1)"},
	}
	for _, input := range cases {
		if err := ValidateContent(input); !errors.Is(err, ErrInvalidContent) {
			t.Errorf("ValidateContent(%q, %q) = %v, want ErrInvalidContent", input.Title, input.Body, err)
		}
	}
}

func TestValidatePresentationMatchesAdminAnnouncementModes(t *testing.T) {
	t.Parallel()
	if got := NormalizePresentation(Presentation{}); got.Format != FormatContent || got.SortOrder != 100 {
		t.Fatalf("default presentation = %+v", got)
	}
	if err := ValidatePresentation(Presentation{Format: FormatContent, SortOrder: 100, Visible: true}, Content{Title: "标题", Body: "正文"}); err != nil {
		t.Fatalf("content presentation rejected: %v", err)
	}
	if err := ValidatePresentation(Presentation{Format: FormatLink, LinkURL: "https://example.invalid/docs", SortOrder: 5}, Content{Title: "标题"}); err != nil {
		t.Fatalf("link presentation rejected: %v", err)
	}
	for _, value := range []Presentation{
		{Format: FormatLink, LinkURL: "javascript:alert(1)"},
		{Format: FormatLink, LinkURL: "https://example.invalid/docs", SortOrder: -1},
		{Format: FormatLink, LinkURL: "https://example.invalid/docs"},
		{Format: FormatContent, LinkURL: "https://example.invalid/docs"},
	} {
		body := Content{Title: "标题"}
		if value.Format == FormatLink && value.LinkURL == "https://example.invalid/docs" && value.SortOrder == 0 {
			continue
		}
		if err := ValidatePresentation(value, body); err == nil {
			t.Errorf("invalid presentation accepted: %+v", value)
		}
	}
}

func TestValidateAudienceRequiresOneExplicitTenantSafeMode(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	groupID := uuid.New()
	for _, audience := range []Audience{
		{All: true},
		{UserIDs: []uuid.UUID{userID}},
		{GroupIDs: []uuid.UUID{groupID}},
		{UserIDs: []uuid.UUID{userID, userID}, GroupIDs: []uuid.UUID{groupID, groupID}},
	} {
		if err := ValidateAudience(audience); err != nil {
			t.Fatalf("valid audience %+v: %v", audience, err)
		}
	}
	for _, audience := range []Audience{
		{},
		{All: true, UserIDs: []uuid.UUID{userID}},
		{UserIDs: []uuid.UUID{uuid.Nil}},
		{GroupIDs: []uuid.UUID{uuid.Nil}},
	} {
		if err := ValidateAudience(audience); !errors.Is(err, ErrInvalidAudience) {
			t.Errorf("ValidateAudience(%+v) = %v, want ErrInvalidAudience", audience, err)
		}
	}
}

func TestValidateGlobalAudienceCoversAllTenantRoleAndUserTargets(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	otherTenantID := uuid.New()
	roleID := uuid.New()
	userID := uuid.New()
	for _, audience := range []GlobalAudience{
		{AllTenants: true},
		{TenantScopeIDs: []uuid.UUID{tenantID}},
		{RoleTargets: []GlobalRoleTarget{{ScopeID: tenantID, RoleID: roleID}}},
		{UserTargets: []GlobalUserTarget{{ScopeID: otherTenantID, UserID: userID}}},
		{
			TenantScopeIDs: []uuid.UUID{tenantID},
			RoleTargets:    []GlobalRoleTarget{{ScopeID: tenantID, RoleID: roleID}},
			UserTargets:    []GlobalUserTarget{{ScopeID: otherTenantID, UserID: userID}},
		},
	} {
		if err := ValidateGlobalAudience(audience); err != nil {
			t.Fatalf("valid global audience %+v: %v", audience, err)
		}
	}
	for _, audience := range []GlobalAudience{
		{},
		{AllTenants: true, TenantScopeIDs: []uuid.UUID{tenantID}},
		{TenantScopeIDs: []uuid.UUID{uuid.Nil}},
		{RoleTargets: []GlobalRoleTarget{{ScopeID: tenantID}}},
		{UserTargets: []GlobalUserTarget{{UserID: userID}}},
	} {
		if err := ValidateGlobalAudience(audience); !errors.Is(err, ErrInvalidAudience) {
			t.Errorf("ValidateGlobalAudience(%+v) = %v, want ErrInvalidAudience", audience, err)
		}
	}
}
