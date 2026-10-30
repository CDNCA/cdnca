package systemothersettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be2: a refused other setting names value.<field> of the save body.
func TestSettingsFieldError(t *testing.T) {
	text := func(value string) *string { return &value }
	number := func(value int) *int { return &value }
	for name, check := range map[string]struct {
		change        func(*Settings)
		field, reason string
	}{
		"source header":  {func(v *Settings) { v.SourceIPHeader = "X-A\nB" }, "value.source_ip_header", fielderr.InvalidFormat},
		"dns protection": {func(v *Settings) { v.DNSProtection = strings.Repeat("a", 2049) }, "value.dns_protection", fielderr.TooLong},
		"repair mode":    {func(v *Settings) { v.RecordRepairMode = "x" }, "value.record_repair_mode", fielderr.Invalid},
		"sync batch":     {func(v *Settings) { v.SyncBatch = 0 }, "value.sync_batch", fielderr.OutOfRange},
		"sync scope":     {func(v *Settings) { v.SyncScope = "x" }, "value.sync_scope", fielderr.Invalid},
		"resource rank":  {func(v *Settings) { v.ResourceRank = 1001 }, "value.resource_rank", fielderr.OutOfRange},
		"http proxy":     {func(v *Settings) { v.HTTPProxy = "a\rb" }, "value.http_proxy", fielderr.InvalidFormat},
		"tcp factor":     {func(v *Settings) { v.TCPFactor = 0 }, "value.tcp_factor", fielderr.OutOfRange},
		"drain":          {func(v *Settings) { v.L4DrainMaxSeconds = number(-1) }, "value.l4_drain_max_seconds", fielderr.OutOfRange},
		"ownership":      {func(v *Settings) { v.DomainOwnershipPolicy = text("x") }, "value.domain_ownership_policy", fielderr.Invalid},
		"notice days":    {func(v *Settings) { v.CertificateExpiryNoticeDays = []int{3, 7} }, "value.certificate_expiry_notice_days", fielderr.Invalid},
	} {
		value := DefaultSettings()
		check.change(&value)
		err := settingsFieldError(value)
		located, ok := fielderr.As(err)
		if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != check.field || located.Reason != check.reason {
			t.Errorf("%s: %v, want %s/%s", name, err, check.field, check.reason)
		}
		if validSettings(value) {
			t.Errorf("%s: validSettings accepted a refused value", name)
		}
	}
	if err := settingsFieldError(DefaultSettings()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}
