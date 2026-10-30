package site

import (
	"errors"
	"testing"
)

// PJ-C05: a refused site write names the request field (error.details.field)
// instead of a bare validation_error; it is still ErrInvalidInput.
func TestNormalizeFieldsNamesRefusedField(t *testing.T) {
	base := func() SiteFields {
		return SiteFields{Domains: []string{"www.example.com"}, HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"},
			HTTPSEnabled: true, Origins: []string{"192.0.2.1"}, Enabled: true}
	}
	enabled := true
	port := 8443
	for name, c := range map[string]struct {
		mutate        func(*SiteFields)
		field, reason string
	}{
		"bad domain":        {func(f *SiteFields) { f.Domains = []string{"not a domain"} }, "domains", "invalid"},
		"bad cname":         {func(f *SiteFields) { f.CNAME = "-bad-" }, "cname", "invalid"},
		"bad http port":     {func(f *SiteFields) { f.HTTPPorts = []string{"99999"} }, "http_listen_ports", "invalid"},
		"bad https port":    {func(f *SiteFields) { f.HTTPSPorts = []string{"abc"} }, "https_listen_ports", "invalid"},
		"https no port":     {func(f *SiteFields) { f.HTTPSPorts = nil }, "https_listen_ports", "required"},
		"port overlap":      {func(f *SiteFields) { f.HTTPSPorts = []string{"80"} }, "https_listen_ports", "overlaps_http"},
		"force without tls": {func(f *SiteFields) { f.ForceHTTPS, f.HTTPSEnabled, f.HTTPSPorts = &enabled, false, nil }, "force_https", "requires_https"},
		"redirect port":     {func(f *SiteFields) { f.HTTPSRedirectPort = &port }, "https_redirect_port", "not_listened"},
		"no origin":         {func(f *SiteFields) { f.Origins = nil }, "origins", "count"},
		"bad origin":        {func(f *SiteFields) { f.Origins = []string{"http://"} }, "origins", "invalid"},
		"duplicate origin":  {func(f *SiteFields) { f.Origins = []string{"192.0.2.1", "192.0.2.1"} }, "origins", "duplicate"},
	} {
		fields := base()
		c.mutate(&fields)
		err := normalizeFields(&fields)
		var fieldErr *FieldError
		if !errors.As(err, &fieldErr) || fieldErr.Field != c.field || fieldErr.Reason != c.reason || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want field %s/%s", name, err, c.field, c.reason)
		}
	}
}
