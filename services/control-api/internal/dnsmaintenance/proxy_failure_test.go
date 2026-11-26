package dnsmaintenance

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

func TestProviderFailureNamesDNSProxy(t *testing.T) {
	if got := providerFailure(&dnsproviderremote.Error{Code: dnsproviderremote.CodeProxyUnavailable}); got != CodeProxyUnavailable {
		t.Fatalf("proxy = %q", got)
	}
	for _, err := range []error{&dnsproviderremote.Error{Code: dnsproviderremote.CodeUnavailable}, errors.New("x")} {
		if got := providerFailure(err); got != CodeProviderUnavailable {
			t.Fatalf("%v = %q", err, got)
		}
	}
}
