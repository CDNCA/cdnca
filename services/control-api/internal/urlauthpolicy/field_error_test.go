package urlauthpolicy

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// fix-fielderr-be4: a refused URL auth policy field is named as sent in the
// (flat) policy body; list entries keep their submitted index.
func TestNormalizeFieldsLocatesField(t *testing.T) {
	for name, check := range map[string]struct {
		mutate        func(*PolicyFields)
		field, reason string
	}{
		"site":            {func(f *PolicyFields) { f.SiteID = uuid.Nil }, "site_id", fielderr.Required},
		"name empty":      {func(f *PolicyFields) { f.Name = " " }, "name", fielderr.Required},
		"name long":       {func(f *PolicyFields) { f.Name = strings.Repeat("名", 129) }, "name", fielderr.TooLong},
		"algorithm":       {func(f *PolicyFields) { f.Algorithm = "md5" }, "algorithm", fielderr.Invalid},
		"signature param": {func(f *PolicyFields) { f.SignatureParameter = "a b" }, "signature_parameter", fielderr.InvalidFormat},
		"expiration":      {func(f *PolicyFields) { f.ExpirationParameter = "" }, "expiration_parameter", fielderr.InvalidFormat},
		"key id param":    {func(f *PolicyFields) { f.KeyIDParameter = "k/1" }, "key_id_parameter", fielderr.InvalidFormat},
		"dup expiration":  {func(f *PolicyFields) { f.ExpirationParameter = f.SignatureParameter }, "expiration_parameter", fielderr.Duplicate},
		"dup key id":      {func(f *PolicyFields) { f.KeyIDParameter = f.SignatureParameter }, "key_id_parameter", fielderr.Duplicate},
		"skew":            {func(f *PolicyFields) { f.MaxClockSkewSeconds = 301 }, "max_clock_skew_seconds", fielderr.OutOfRange},
		"validity zero":   {func(f *PolicyFields) { f.MaxValiditySeconds = 0 }, "max_validity_seconds", fielderr.OutOfRange},
		"uses":            {func(f *PolicyFields) { f.MaxSignatureUses = 1_000_001 }, "max_signature_uses", fielderr.OutOfRange},
		"exclusions max":  {func(f *PolicyFields) { f.ExcludedQueryParameters = make([]string, 33) }, "excluded_query_parameters", fielderr.OutOfRange},
		"exclusion bad":   {func(f *PolicyFields) { f.ExcludedQueryParameters = []string{"utm", "a b"} }, "excluded_query_parameters[1]", fielderr.InvalidFormat},
		"exclusion auth":  {func(f *PolicyFields) { f.ExcludedQueryParameters = []string{f.SignatureParameter} }, "excluded_query_parameters[0]", fielderr.Invalid},
		"exclusion dup":   {func(f *PolicyFields) { f.ExcludedQueryParameters = []string{"z", "utm", "utm"} }, "excluded_query_parameters[2]", fielderr.Duplicate},
		"proxies max":     {func(f *PolicyFields) { f.TrustedProxyCIDRs = make([]string, 65) }, "trusted_proxy_cidrs", fielderr.OutOfRange},
		"proxy bad":       {func(f *PolicyFields) { f.TrustedProxyCIDRs = []string{"10.0.0.0/8", "10.0.0.999/24"} }, "trusted_proxy_cidrs[1]", fielderr.InvalidFormat},
		"proxy mapped":    {func(f *PolicyFields) { f.TrustedProxyCIDRs = []string{"::ffff:192.0.2.1/128"} }, "trusted_proxy_cidrs[0]", fielderr.Invalid},
		"proxy dup":       {func(f *PolicyFields) { f.TrustedProxyCIDRs = []string{"10.0.0.1/8", "10.0.0.0/8"} }, "trusted_proxy_cidrs[1]", fielderr.Duplicate},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validFields()
			check.mutate(&fields)
			err := normalizeFields(&fields)
			located, ok := fielderr.As(err)
			if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != check.field || located.Reason != check.reason {
				t.Fatalf("error = %v, want %s/%s", err, check.field, check.reason)
			}
		})
	}
}
