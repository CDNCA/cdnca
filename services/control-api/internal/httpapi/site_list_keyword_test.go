package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// 只认 ID 的「基础套餐」「网站ID」也可按名称过滤。
func TestParseSiteListFilterKeywords(t *testing.T) {
	filter, err := parseSiteListFilter(httptest.NewRequest("GET", "/v1/sites?package=%E4%BC%81%E4%B8%9A&site=example", nil))
	if err != nil || filter.Package != "企业" || filter.Site != "example" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	actor := site.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	normalized, err := site.NormalizeListFilter(actor, site.ListFilter{Page: 1, Limit: 20, Package: " 企业 ", Site: " Example.TEST "})
	if err != nil || normalized.Package != "企业" || normalized.Site != "example.test" {
		t.Fatalf("normalized=%+v err=%v", normalized, err)
	}
	for name, candidate := range map[string]site.ListFilter{
		"long package": {Page: 1, Limit: 20, Package: strings.Repeat("a", 129)},
		"long site":    {Page: 1, Limit: 20, Site: strings.Repeat("a", 254)},
	} {
		if _, err := site.NormalizeListFilter(actor, candidate); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
