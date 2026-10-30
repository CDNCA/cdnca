package systemconfig

import (
	"os"
	"strings"
	"testing"
)

func TestOPS02ActivationPublishesBeforeSwitchingActiveRevision(t *testing.T) {
	body, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "func (s *Service) activate(")
	end := strings.Index(source[start:], "func (s *Service) rollback(")
	if start < 0 || end < 0 {
		t.Fatal("activation source boundary not found")
	}
	activation := source[start : start+end]
	publish := strings.Index(activation, "s.publisher.PublishActivation(")
	switchActive := strings.Index(activation, "SET status='active'")
	if publish < 0 || switchActive < 0 || publish > switchActive {
		t.Fatal("immutable Edge publication must complete in the activation transaction before the active revision changes")
	}
	for _, required := range []string{"current.SnapshotSHA256", "current.Configuration", "request.Revision", "actor"} {
		if !strings.Contains(activation, required) {
			t.Errorf("activation publication is not exactly source-bound to %q", required)
		}
	}
}
