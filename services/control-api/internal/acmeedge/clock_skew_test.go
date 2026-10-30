package acmeedge

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
)

// Same comparison as the deployment status: a node receipt stamped
// by a clock behind the controller's dispatched event was an invalid
// transition. Within the skew it is ordered at the dispatched time; beyond it
// stays earlier and is refused.
func TestReceiptOrderedAfterPredecessorWithinClockSkew(t *testing.T) {
	dispatched := time.Now().UTC().Truncate(time.Microsecond)
	if got := orderAfterPredecessor(dispatched.Add(-30*time.Millisecond), dispatched); !got.Equal(dispatched) {
		t.Fatalf("node 30ms behind: %s, want %s", got, dispatched)
	}
	if ahead := dispatched.Add(30 * time.Millisecond); !orderAfterPredecessor(ahead, dispatched).Equal(ahead) {
		t.Fatal("node ahead lost its own time")
	}
	far := dispatched.Add(-edgestatus.CrossHostClockSkew - time.Millisecond)
	if got := orderAfterPredecessor(far, dispatched); !got.Equal(far) {
		t.Fatalf("beyond the skew: %s, want %s unchanged", got, far)
	}
}
