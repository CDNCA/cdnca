package edgeconfig

import (
	"slices"
	"testing"
)

func TestNormalizeAccessLogFields(t *testing.T) {
	got, err := NormalizeAccessLogFields(AccessLogFields{Fields: []string{"ja4", "referer", "client_family"}})
	if err != nil || !slices.Equal(got.Fields, []string{"client_family", "referer", "ja4"}) {
		t.Fatalf("normalized = %v, %v", got, err)
	}
	if got, err := NormalizeAccessLogFields(AccessLogFields{Fields: []string{}}); err != nil || len(got.Fields) != 0 {
		t.Fatalf("empty selection = %v, %v", got, err)
	}
	for _, invalid := range [][]string{nil, {"host"}, {"referer", "referer"}, {"Referer"}} {
		if _, err := NormalizeAccessLogFields(AccessLogFields{Fields: invalid}); err == nil {
			t.Fatalf("%v accepted", invalid)
		}
	}
}

func TestAccessLogFieldsDefaultAndHeaders(t *testing.T) {
	normalized, err := NormalizeAccessLogFields(AccessLogFields{Fields: DefaultAccessLogFields})
	if err != nil || !slices.Equal(normalized.Fields, DefaultAccessLogFields) {
		t.Fatalf("the default is not in catalog order: %v", normalized.Fields)
	}
	effective := EffectiveAccessLogFields(nil)
	if effective.Has(AccessLogFieldUpstreamAddr) || !effective.Has(AccessLogFieldReferer) {
		t.Fatalf("default = %v", effective.Fields)
	}
	request, response := effective.Headers()
	if !slices.Equal(request, []string{"Referer", "User-Agent"}) || !slices.Equal(response, []string{"Content-Type"}) {
		t.Fatalf("default headers = %v / %v", request, response)
	}
	request, response = AccessLogFields{Fields: []string{}}.Headers()
	if request == nil || response == nil || len(request)+len(response) != 0 {
		t.Fatal("no header field selected must be two empty lists")
	}
}

func TestMergeCaptureHeaders(t *testing.T) {
	got := MergeCaptureHeaders([]string{"X-Trace", "user-agent"}, []string{"Referer", "User-Agent"})
	if !slices.Equal(got, []string{"Referer", "User-Agent", "X-Trace"}) {
		t.Fatalf("merged = %v", got)
	}
	if got := MergeCaptureHeaders(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("empty merge = %v", got)
	}
}

// fix-decide1027b 第1项：是否拦截页可选，默认记录（行为与可选前一致）。
func TestAccessLogFieldBlockPageDefaultOn(t *testing.T) {
	field := accessLogField(AccessLogFieldBlockPage)
	if field == nil || field.Header != "" || field.Group != AccessLogGroupSecurity {
		t.Fatalf("block_page catalog entry = %+v", field)
	}
	if !EffectiveAccessLogFields(nil).Has(AccessLogFieldBlockPage) {
		t.Fatal("block_page not in the default selection")
	}
}
