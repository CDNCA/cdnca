package nodesshinstall

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

type exitStatus int

func (status exitStatus) Error() string   { return fmt.Sprintf("exit %d", int(status)) }
func (status exitStatus) ExitStatus() int { return int(status) }

// Exit 3 with the installer's last "install-state: <state>" is an installed
// node that does not serve yet (waiting for its first ticket, installation
// banned, or ticket expired), each shown on its own, not install_failed.
func TestInstalledNotServing(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		state string
		want  string
	}{
		{"exit 3 pending initialization", exitStatus(3), "installed_pending_initialization", ResultPendingInitialization},
		{"exit 1 with pending initialization line", exitStatus(1), "installed_pending_initialization", ""},
		{"exit 3 pending ticket", exitStatus(3), "installed_pending_ticket", ResultPendingTicket},
		{"wrapped exit 3", fmt.Errorf("run: %w", exitStatus(3)), "installed_pending_ticket", ResultPendingTicket},
		{"exit 3 banned", exitStatus(3), "installed_banned", ResultBanned},
		{"exit 3 ticket expired", exitStatus(3), "installed_ticket_expired", ResultTicketExpired},
		{"exit 3 resume failed", exitStatus(3), "installed_resume_failed", ResultResumeFailed},
		{"exit 3 serving line", exitStatus(3), "serving", ""},
		{"exit 3 unknown state", exitStatus(3), "installed_other", ""},
		{"exit 3 without state line", exitStatus(3), "", ""},
		{"exit 1 with banned line", exitStatus(1), "installed_banned", ""},
		{"exit 1 with pending line", exitStatus(1), "installed_pending_ticket", ""},
		{"network error", errors.New("dial tcp: refused"), "installed_ticket_expired", ""},
	} {
		if got := installedNotServing(test.err, test.state); got != test.want {
			t.Errorf("%s: got %q, want %q", test.name, got, test.want)
		}
	}
	if ResultBanned != "installed_banned" || ResultTicketExpired != "installed_ticket_expired" || ResultResumeFailed != "installed_resume_failed" ||
		ResultPendingInitialization != "installed_pending_initialization" {
		t.Fatalf("result codes drifted from install-node.sh: %q %q %q", ResultBanned, ResultTicketExpired, ResultPendingInitialization)
	}
	// The SSH session returns *ssh.ExitError (ExitStatus via Waitmsg).
	var real error = &ssh.ExitError{}
	var exit interface{ ExitStatus() int }
	if !errors.As(real, &exit) {
		t.Fatal("*ssh.ExitError does not expose ExitStatus")
	}
	if installStatePrefix != "[cdnca-edge] install-state: " {
		t.Fatalf("installStatePrefix = %q", installStatePrefix)
	}
}
