package installationban

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PF09: the node page shows each node's last ticket and the days left.
func TestEvaluateNodeTicket(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	issued := now.Add(-36 * time.Hour)
	notAfter := issued.Add(7 * 24 * time.Hour)
	reported := now.Add(-time.Minute)
	valid := EvaluateNodeTicket("n1", &NodeTicketRow{Status: "serving", IssuedAt: &issued, NotAfter: &notAfter,
		ReportedAt: reported}, now)
	if valid.State != NodeTicketValid || valid.DaysLeft == nil || *valid.DaysLeft != 5 || !valid.IssuedAt.Equal(issued) ||
		!valid.NotAfter.Equal(notAfter) || valid.NodeStatus != "serving" {
		t.Fatalf("valid = %+v", valid)
	}
	lastDay := EvaluateNodeTicket("n1", &NodeTicketRow{Status: "serving", IssuedAt: &issued, NotAfter: &notAfter,
		ReportedAt: reported}, notAfter.Add(-time.Hour))
	if lastDay.State != NodeTicketValid || *lastDay.DaysLeft != 0 {
		t.Fatalf("last day = %+v", lastDay)
	}
	expired := EvaluateNodeTicket("n1", &NodeTicketRow{Status: "service_ticket_expired", IssuedAt: &issued,
		NotAfter: &notAfter, ReportedAt: reported}, notAfter)
	if expired.State != NodeTicketExpired || *expired.DaysLeft != 0 {
		t.Fatalf("expired = %+v", expired)
	}
	none := EvaluateNodeTicket("n2", &NodeTicketRow{Status: "no_ticket", ReportedAt: reported}, now)
	if none.State != NodeTicketNone || none.IssuedAt != nil || none.DaysLeft != nil || none.ReportedAt == nil {
		t.Fatalf("no ticket = %+v", none)
	}
	if unknown := EvaluateNodeTicket("n3", nil, now); unknown.State != NodeTicketUnknown || unknown.ReportedAt != nil {
		t.Fatalf("unknown = %+v", unknown)
	}
}

func TestReceiptTicketTimes(t *testing.T) {
	issued := time.Unix(1_900_000_000, 0).UTC()
	receipt := &agentv1.InstallationBanReceipt{TicketIssuedTime: timestamppb.New(issued),
		TicketNotAfterTime: timestamppb.New(issued.Add(7 * 24 * time.Hour))}
	if got, end, err := ReceiptTicketTimes(receipt); err != nil || !got.Equal(issued) || !end.Equal(issued.Add(7*24*time.Hour)) {
		t.Fatalf("both set = %v %v %v", got, end, err)
	}
	if got, end, err := ReceiptTicketTimes(&agentv1.InstallationBanReceipt{}); err != nil || got != nil || end != nil {
		t.Fatalf("none = %v %v %v", got, end, err)
	}
	if _, _, err := ReceiptTicketTimes(&agentv1.InstallationBanReceipt{TicketIssuedTime: timestamppb.New(issued)}); err == nil {
		t.Fatal("half set accepted")
	}
	if _, _, err := ReceiptTicketTimes(&agentv1.InstallationBanReceipt{TicketIssuedTime: timestamppb.New(issued),
		TicketNotAfterTime: timestamppb.New(issued)}); err == nil {
		t.Fatal("not_after == issued accepted")
	}
}
