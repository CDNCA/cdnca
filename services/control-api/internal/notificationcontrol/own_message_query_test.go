package notificationcontrol

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeOwnMessageQuery(t *testing.T) {
	site := uuid.NewString()
	got, err := normalizeOwnMessageQuery(OwnMessageQuery{Type: "security.attack.detected", SiteID: site, Limit: "20", Offset: "40"})
	if err != nil || got.Type != "security.attack.detected" || got.SiteID == nil || got.SiteID.String() != site ||
		got.PackageID != nil || got.Limit != 20 || got.Offset != 40 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if got, err := normalizeOwnMessageQuery(OwnMessageQuery{}); err != nil || got.Limit != defaultMessageQueryLimit || got.Offset != 0 {
		t.Fatalf("default=%+v err=%v", got, err)
	}
	for name, raw := range map[string]OwnMessageQuery{
		"invalid": {Invalid: true}, "type": {Type: "Bad Type"}, "site": {SiteID: "site-1"},
		"nilPackage": {PackageID: uuid.Nil.String()}, "upperSite": {SiteID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
		"limit0": {Limit: "0"}, "limit": {Limit: "101"}, "offset": {Offset: "-1"}, "offsetMax": {Offset: "10001"}, "padded": {Limit: "05"},
	} {
		if _, err := normalizeOwnMessageQuery(raw); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s err=%v", name, err)
		}
	}
}
