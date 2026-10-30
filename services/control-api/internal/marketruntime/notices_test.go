package marketruntime

import (
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/notice"
)

// fix-nm03: every market notice kind has a template context, the upstream
// pause compensation notice carries its amount fields, and the renewal stop
// and resume notices use the v2 templates (migration 558) that explain
// upstream_paused.
func TestNoticeKindsHaveTemplates(t *testing.T) {
	for _, kind := range notice.Kinds {
		if _, ok := noticeVariables[kind]; !ok {
			t.Errorf("%s has no template variables", kind)
		}
	}
	n := notice.Notice{Kind: notice.KindRenewalCompensated, Values: map[string]string{
		notice.ValueOffer: "o", notice.ValueAction: "extended", notice.ValueObserved: "1800", notice.ValueAt: "2026-10-28T00:00:00Z"}}
	ctx, err := NoticeContext(n)
	if err != nil {
		t.Fatal(err)
	}
	_, observed := ctx["observed"]
	_, at := ctx["at"]
	_, currency := ctx["currency"]
	if len(ctx) != 6 || !observed || !at || !currency {
		t.Errorf("compensation context: %v", ctx)
	}
	for kind, want := range map[string]uint64{
		notice.KindRenewalStopped: 2, notice.KindRenewalResumed: 2, notice.KindRenewalCompensated: 1, notice.KindFeedbackOpened: 1,
	} {
		if got := noticeTemplateVersionOf(kind); got != want {
			t.Errorf("%s template version %d, want %d", kind, got, want)
		}
	}
}
