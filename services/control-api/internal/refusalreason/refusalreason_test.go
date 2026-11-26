package refusalreason

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestWrapKeepsErrorIdentityAndText(t *testing.T) {
	base := errors.New("human invalid")
	wrapped := Wrap(base, "captcha_expired")
	if !errors.Is(wrapped, base) || wrapped.Error() != base.Error() {
		t.Fatalf("wrapped = %v", wrapped)
	}
	if got := Of(fmt.Errorf("outer: %w", wrapped)); got != "captcha_expired" {
		t.Fatalf("Of = %q", got)
	}
	if got := Of(Wrap(Wrap(base, "inner"), "outer")); got != "outer" {
		t.Fatalf("outermost reason = %q", got)
	}
	if Wrap(base, "") != base || Wrap(nil, "x") != nil || Of(base) != "" || Of(nil) != "" {
		t.Fatal("empty reason / nil error must pass through")
	}
}

func TestRecordNeedsRecorder(t *testing.T) {
	Record(context.Background(), "captcha_expired") // no recorder: no-op
	if Recorded(context.Background()) != "" {
		t.Fatal("recorded without recorder")
	}
	ctx := WithRecorder(context.Background())
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	Record(child, "captcha_consumed")
	Record(child, "")
	if got := Recorded(ctx); got != "captcha_consumed" {
		t.Fatalf("Recorded = %q", got)
	}
}
