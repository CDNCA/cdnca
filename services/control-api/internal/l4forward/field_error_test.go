package l4forward

import (
	"errors"
	"testing"
)

// fp-role L4-006：参数错误要能说出是哪个字段，而且仍是 ErrInvalidInput（API 400）。
func TestNormalizeFieldsNamesTheRefusedField(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Fields)
		field  string
		reason string
	}{
		{name: "name", mutate: func(f *Fields) { f.Name = "a\nb" }, field: "name", reason: "invalid"},
		{name: "remark", mutate: func(f *Fields) { f.Remark = "a\x00" }, field: "remark", reason: "invalid"},
		{name: "no upstream", mutate: func(f *Fields) { f.UpstreamAddress, f.UpstreamHost = "", "" }, field: "upstream_address", reason: "required"},
		{name: "bad address", mutate: func(f *Fields) { f.UpstreamAddress, f.UpstreamHost = "0.0.0.0", "" }, field: "upstream_address", reason: "invalid"},
		{name: "address with DNS", mutate: func(f *Fields) {
			f.UpstreamAddress, f.UpstreamHost = "192.0.2.10", ""
			f.DNS = DNSPolicy{PositiveMinTTLSeconds: 30}
		}, field: "dns_policy", reason: "invalid"},
		{name: "bad host", mutate: func(f *Fields) { f.UpstreamAddress, f.UpstreamHost = "", "bad host" }, field: "upstream_host", reason: "invalid"},
		{name: "ACL", mutate: func(f *Fields) { f.ACL = &ACL{DefaultAction: "drop"} }, field: "acl", reason: "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := validFields()
			test.mutate(&fields)
			err := normalizeFields(&fields)
			var located *FieldError
			if !errors.As(err, &located) || located.Field != test.field || located.Reason != test.reason {
				t.Fatalf("normalizeFields error = %v, want field %s/%s", err, test.field, test.reason)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("field error %v does not unwrap to ErrInvalidInput", err)
			}
			if kept := locatedOrInvalid(err); !errors.As(kept, &located) || located.Field != test.field {
				t.Fatalf("locatedOrInvalid dropped the field: %v", kept)
			}
		})
	}
}
