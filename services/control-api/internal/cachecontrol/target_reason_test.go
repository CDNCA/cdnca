package cachecontrol

import (
	"errors"
	"testing"
)

// ADD-10: each refused target names its 1-based ordinal and a stable reason;
// the error is still ErrInvalidInput for callers that only check that.
func TestNormalizeTargetsReportsOrdinalAndReason(t *testing.T) {
	site := siteDescriptor{Domain: "example.com", Domains: []string{"example.com"}, HTTPPorts: []string{"80"}, HTTPSPorts: []string{}}
	for _, test := range []struct {
		name    string
		targets []string
		prefix  bool
		ordinal int
		reason  string
	}{
		{"host not served", []string{"http://example.com/a", "http://other.test/b"}, false, 2, TargetReasonHostNotServed},
		{"https listener off", []string{"https://example.com/a"}, false, 1, TargetReasonListenerNotEnabled},
		{"port not listened", []string{"http://example.com:8080/a"}, false, 1, TargetReasonListenerNotEnabled},
		{"not a url", []string{"ftp://example.com/a"}, false, 1, TargetReasonInvalidURL},
		{"directory with query", []string{"http://example.com/assets/?v=1"}, true, 1, TargetReasonPathInvalid},
		{"duplicate after canonicalization", []string{"http://example.com/a", "http://EXAMPLE.com:80/a"}, false, 2, TargetReasonDuplicate},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetType := TargetExactURL
			if test.prefix {
				targetType = TargetDirectoryPrefix
			}
			_, err := normalizeTargets(test.targets, ActionPurge, targetType, site)
			var targetErr *TargetError
			if !errors.As(err, &targetErr) || targetErr.Ordinal != test.ordinal || targetErr.Reason != test.reason ||
				!errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
