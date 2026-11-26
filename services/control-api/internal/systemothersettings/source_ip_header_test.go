package systemothersettings

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// 源IP请求头 takes "" (direct) or one of the four
// headers; a stored value outside them (written while nothing read the
// field) reads as "" so the other settings stay readable.
func TestSourceIPHeaderSettingValues(t *testing.T) {
	if DefaultSettings().SourceIPHeader != "" {
		t.Fatalf("default = %q, want direct", DefaultSettings().SourceIPHeader)
	}
	for _, header := range []string{"", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For", "X-Real-IP"} {
		value := DefaultSettings()
		value.SourceIPHeader = header
		if err := settingsFieldError(value); err != nil {
			t.Errorf("%q refused: %v", header, err)
		}
	}
	for _, header := range []string{"cf-connecting-ip", "X-Client-IP", " CF-Connecting-IP", "Ali-Cdn-Real-Ip"} {
		value := DefaultSettings()
		value.SourceIPHeader = header
		if settingsFieldError(value) == nil {
			t.Errorf("%q accepted", header)
		}
	}
	value, err := decodeSettings([]byte(`{"source_ip_header":"X-Client-IP","api_key_enabled":false}`))
	if err != nil || value.SourceIPHeader != "" || value.APIKeyEnabled || !validSettings(value) {
		t.Fatalf("legacy header: %+v %v", value, err)
	}
}

func TestSourceIPHeaderReader(t *testing.T) {
	ctx := context.Background()
	for name, check := range map[string]struct {
		query apiKeyStatusQuerier
		want  string
		fails bool
	}{
		"no row":     {query: apiKeyStatusQuerier{err: pgx.ErrNoRows}},
		"direct":     {query: apiKeyStatusQuerier{raw: []byte(`{"source_ip_header":""}`)}},
		"missing":    {query: apiKeyStatusQuerier{raw: []byte(`{"api_key_enabled":true}`)}},
		"cloudflare": {query: apiKeyStatusQuerier{raw: []byte(`{"source_ip_header":"CF-Connecting-IP"}`)}, want: "CF-Connecting-IP"},
		"unknown":    {query: apiKeyStatusQuerier{raw: []byte(`{"source_ip_header":"X-Client-IP"}`)}},
		"broken":     {query: apiKeyStatusQuerier{raw: []byte(`[]`)}, fails: true},
	} {
		got, err := SourceIPHeader(ctx, check.query)
		if got != check.want || (err != nil) != check.fails {
			t.Errorf("%s: %q %v, want %q (fails %v)", name, got, err, check.want, check.fails)
		}
	}
	if _, err := SourceIPHeader(ctx, nil); err == nil {
		t.Fatal("nil querier accepted")
	}
}
