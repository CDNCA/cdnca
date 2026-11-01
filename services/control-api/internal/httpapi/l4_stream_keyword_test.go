package httpapi

import (
	"net/http/httptest"
	"testing"
)

// 四层「转发ID」「用户ID」也可按名称过滤。
func TestParseStreamListFilterKeywords(t *testing.T) {
	filter, err := parseStreamListFilter(httptest.NewRequest("GET", "/v1/streams?forward=web&owner=bob", nil))
	if err != nil || filter.Forward != "web" || filter.Owner != "bob" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	if _, err := parseStreamListFilter(httptest.NewRequest("GET", "/v1/streams?owner=%20", nil)); err == nil {
		t.Fatal("blank owner accepted")
	}
}
