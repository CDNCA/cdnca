package notificationcontrol

import (
	"errors"
	"strings"
	"testing"
)

// the user/package/site filters also take a name:
// keyword parameters match names or the exact display ID.
func TestNormalizeMessageQueryKeywords(t *testing.T) {
	query, err := normalizeMessageQuery(MessageQuery{User: "张三", Package: "基础套餐", Site: "example.test"})
	if err != nil || query.User != "张三" || query.Package != "基础套餐" || query.Site != "example.test" {
		t.Fatalf("query=%+v err=%v", query, err)
	}
	for name, candidate := range map[string]MessageQuery{
		"control user": {User: "a\tb"}, "padded package": {Package: " x"}, "long site": {Site: strings.Repeat("a", 129)},
	} {
		if _, err := normalizeMessageQuery(candidate); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s err=%v", name, err)
		}
	}
}

func TestNormalizeOwnMessageQueryKeywords(t *testing.T) {
	query, err := normalizeOwnMessageQuery(OwnMessageQuery{Site: "example.test", Package: "12"})
	if err != nil || query.Site != "example.test" || query.Package != "12" {
		t.Fatalf("query=%+v err=%v", query, err)
	}
	for name, candidate := range map[string]OwnMessageQuery{
		"control site": {Site: "a\nb"}, "long package": {Package: strings.Repeat("a", 129)},
	} {
		if _, err := normalizeOwnMessageQuery(candidate); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s err=%v", name, err)
		}
	}
}
