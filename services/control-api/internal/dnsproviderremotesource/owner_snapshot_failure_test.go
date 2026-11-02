package dnsproviderremotesource

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

func TestOwnerSnapshotFailureKeepsUnavailableAndCode(t *testing.T) {
	err := error(OwnerSnapshotFailure{Code: "dns_zone_not_hosted"})
	var coded interface{ FailureCode() string }
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &coded) || coded.FailureCode() != "dns_zone_not_hosted" {
		t.Fatalf("OwnerSnapshotFailure = %v, want ErrUnavailable with code dns_zone_not_hosted", err)
	}
}

func TestDefinitiveSnapshotFailureFailsOnlyAnswersARetryCannotChange(t *testing.T) {
	for _, test := range []struct {
		code dnsproviderremote.ErrorCode
		want bool
	}{
		{dnsproviderremote.CodeZoneNotHosted, true},
		{dnsproviderremote.CodeCredentialsRejected, true},
		{dnsproviderremote.CodeUnsupported, true},
		{dnsproviderremote.CodeRateLimited, false},
		{dnsproviderremote.CodeTimeout, false},
		{dnsproviderremote.CodeUnavailable, false},
	} {
		err := fmt.Errorf("list: %w", &dnsproviderremote.Error{Code: test.code})
		failure, ok := definitiveSnapshotFailure(err)
		if ok != test.want || (ok && failure.FailureCode() != string(test.code)) {
			t.Fatalf("definitiveSnapshotFailure(%s) = (%v,%v), want %v", test.code, failure, ok, test.want)
		}
	}
	if _, ok := definitiveSnapshotFailure(errors.New("plain")); ok {
		t.Fatal("an error of no known kind must stay retryable")
	}
}
