package identityverificationhttp

import (
	"testing"

	"github.com/google/uuid"
)

func TestSettlementRequeueIsNotAPublicHTTPRoute(t *testing.T) {
	path := apiPrefix + "/settlements/" + uuid.NewString() + "/requeue"
	if route, matched := resolveRoute(path); matched {
		t.Fatalf("hidden settlement requeue route matched: %#v", route)
	}
}
