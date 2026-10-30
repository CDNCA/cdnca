package edgepublish

import (
	"os"
	"strings"
	"testing"
)

func TestHTTPPolicyWriterAndPublisherUseOneLockOrder(t *testing.T) {
	service, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(service)
	start := strings.Index(body, "func (s *Service) publishAuthorizedTx(")
	if start < 0 {
		t.Fatal("publishAuthorizedTx source boundary not found")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end <= 0 {
		t.Fatal("publishAuthorizedTx source boundary not found")
	}
	body = body[start : start+1+end]
	advisory := strings.Index(body, "lockHTTPPolicyPublicationFacts(ctx, tx, request.ConfigurationScopeID)")
	edgeScope := strings.Index(body, "lockConfigurationScope(ctx, tx, request.ConfigurationScopeID, now)")
	if advisory < 0 || edgeScope < 0 || advisory > edgeScope {
		t.Fatalf("publisher lock order must be HTTP policy advisory then edge scope row: advisory=%d edge=%d", advisory, edgeScope)
	}
}
