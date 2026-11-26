package certnotify

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestValidNoticeDays(t *testing.T) {
	for _, days := range [][]int{{30}, {30, 14, 7, 3, 1}, {60, 1}, DefaultNoticeDays} {
		if !ValidNoticeDays(days) {
			t.Fatalf("%v rejected", days)
		}
	}
	for _, days := range [][]int{nil, {}, {0}, {61}, {7, 14}, {7, 7}, {9, 8, 7, 6, 5, 4, 3, 2, 1}} {
		if ValidNoticeDays(days) {
			t.Fatalf("%v accepted", days)
		}
	}
}

func TestDomainListAndReason(t *testing.T) {
	if got := domainList([]string{"b.test", "a.test"}); got != notification.LocalizedValue("a.test、b.test", "a.test, b.test") {
		t.Fatalf("%+v", got)
	}
	if got := domainList([]string{"d", "c", "b", "a"}); got != notification.LocalizedValue("a、b、c等4个", "a, b, c (4 in total)") {
		t.Fatal(got)
	}
	if got := failureReason("acme_rate_limited"); got != "证书签发请求过于频繁" {
		t.Fatal(got)
	}
	if got := failureReason("acme_weird"); got != "签发失败（acme_weird）" {
		t.Fatal(got)
	}
	if got := failureReasonEN("acme_weird"); got != "Issuance failed (acme_weird)" {
		t.Fatal(got)
	}
}
