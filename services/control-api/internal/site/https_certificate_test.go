package site

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type boundRow struct{ bound bool }

func (r boundRow) Scan(dest ...any) error { *dest[0].(*bool) = r.bound; return nil }

type boundQueryer struct {
	bound bool
	calls int
}

func (q *boundQueryer) QueryRow(context.Context, string, ...any) pgx.Row {
	q.calls++
	return boundRow{q.bound}
}

// be-gap-2 WEB-C01/C05: HTTPS / forced HTTPS can only be turned on with a bound certificate.
func TestCheckHTTPSCertificate(t *testing.T) {
	on, off := true, false
	for name, c := range map[string]struct {
		httpsBefore, forceBefore bool
		fields                   SiteFields
		bound                    bool
		field                    string
		queried                  bool
	}{
		"turn HTTPS on without certificate":  {fields: SiteFields{HTTPSEnabled: true}, field: "https_enabled", queried: true},
		"turn HTTPS on with certificate":     {fields: SiteFields{HTTPSEnabled: true}, bound: true, queried: true},
		"turn forced HTTPS on without":       {httpsBefore: true, fields: SiteFields{HTTPSEnabled: true, ForceHTTPS: &on}, field: "force_https", queried: true},
		"HTTPS and forced on: HTTPS named":   {fields: SiteFields{HTTPSEnabled: true, ForceHTTPS: &on}, field: "https_enabled", queried: true},
		"keep HTTPS on (unbound later)":      {httpsBefore: true, forceBefore: true, fields: SiteFields{HTTPSEnabled: true, ForceHTTPS: &on}},
		"turn HTTPS off":                     {httpsBefore: true, fields: SiteFields{ForceHTTPS: &off}},
		"forced HTTPS omitted keeps current": {httpsBefore: true, fields: SiteFields{HTTPSEnabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			q := &boundQueryer{bound: c.bound}
			err := checkHTTPSCertificate(context.Background(), q, uuid.New(), c.httpsBefore, c.forceBefore, c.fields)
			var fieldErr *FieldError
			if c.field == "" && err != nil || c.field != "" && (!errors.As(err, &fieldErr) || fieldErr.Field != c.field ||
				fieldErr.Reason != ReasonCertificateRequired || !errors.Is(err, ErrInvalidInput)) {
				t.Fatalf("err=%v want field %q", err, c.field)
			}
			if (q.calls > 0) != c.queried {
				t.Fatalf("queried=%d want %v", q.calls, c.queried)
			}
		})
	}
}
