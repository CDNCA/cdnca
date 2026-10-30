package dnsproviderremotesource

import (
	"errors"
	"testing"
)

func TestOwnerSnapshotFailureKeepsUnavailableAndCode(t *testing.T) {
	err := error(OwnerSnapshotFailure{Code: "dns_zone_not_hosted"})
	var coded interface{ FailureCode() string }
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &coded) || coded.FailureCode() != "dns_zone_not_hosted" {
		t.Fatalf("OwnerSnapshotFailure = %v, want ErrUnavailable with code dns_zone_not_hosted", err)
	}
}
