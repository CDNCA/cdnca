//go:build integration

package tickets

import (
	"errors"
	"testing"
	"time"
)

// TestTicketStaffStatusAndDelete (fix-ticketops): staff move a ticket through
// every status (待处理/处理中/待用户回复/已解决/已关闭), close it, and soft-delete
// it; a deleted ticket is gone from all surfaces, its attachment can no longer
// be downloaded, it cannot be changed, and the delete is audited.
func TestTicketStaffStatusAndDelete(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	image, err := f.service.Upload(ctx, f.customer, false, "r", UploadInput{FileName: "a.png", MIMEType: "image/png", Body: pngBody})
	if err != nil {
		t.Fatal(err)
	}
	created := f.create(t, f.customer, "ops-1", CreateInput{AttachmentIDs: []string{image.ID}})
	id := created.Ticket.ID
	revision := created.Ticket.Revision
	for _, status := range []string{StatusProcessing, StatusPendingCustomer, StatusResolved, StatusOpen, StatusClosed} {
		next, err := f.service.Update(ctx, f.manager, "r", id, UpdateInput{ExpectedRevision: revision, Status: ptr(status)})
		if err != nil || next.Ticket.Status != status || (status == StatusClosed) != (next.Ticket.ClosedAt != nil) ||
			(status == StatusResolved) != (next.Ticket.ResolvedAt != nil) {
			t.Fatalf("staff status %s = %+v, %v", status, next.Ticket, err)
		}
		revision = next.Ticket.Revision
	}
	// Reader and customer cannot delete.
	if err := f.service.Delete(ctx, f.reader, "r", id); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("reader delete = %v", err)
	}
	if err := f.service.Delete(ctx, f.customer, "r", id); err == nil {
		t.Fatal("customer delete accepted")
	}
	if err := f.service.Delete(ctx, f.manager, "r", id); err != nil {
		t.Fatalf("delete = %v", err)
	}
	if err := f.service.Delete(ctx, f.manager, "r", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete again = %v", err)
	}
	for _, view := range []struct {
		actor Actor
		staff bool
	}{{f.manager, true}, {f.customer, false}} {
		if _, err := f.service.Get(ctx, view.actor, view.staff, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get deleted (staff=%v) = %v", view.staff, err)
		}
		page, err := f.service.List(ctx, view.actor, view.staff, Filter{})
		if err != nil || page.Total != 0 {
			t.Fatalf("list after delete (staff=%v) = %+v, %v", view.staff, page, err)
		}
		if _, err := f.service.Open(ctx, view.actor, view.staff, image.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("download deleted attachment (staff=%v) = %v", view.staff, err)
		}
	}
	if summary, err := f.service.Summary(ctx, f.manager, true); err != nil || summary.Unread != 0 || summary.Pending != 0 {
		t.Fatalf("staff summary = %+v, %v", summary, err)
	}
	if _, err := f.service.Update(ctx, f.manager, "r", id, UpdateInput{ExpectedRevision: revision, Status: ptr(StatusOpen)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update deleted = %v", err)
	}
	if _, err := f.service.Reopen(ctx, f.customer, "r", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reopen deleted = %v", err)
	}
	// The row stays (soft delete); the database refuses any later change.
	if _, err := f.pool.Exec(ctx, `UPDATE tickets SET subject='x' WHERE id=$1`, id); err == nil {
		t.Fatal("deleted ticket was changed")
	}
	var audited int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='ticket.delete' AND resource_id=$1`, id).
		Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("ticket.delete audit = %d, %v", audited, err)
	}
	// A platform administrator without tickets.* may delete too (tenantaccess rule).
	other := f.create(t, f.customer, "ops-2", CreateInput{})
	admin := seedActor(t, f.pool, f.platformScope, time.Now().UTC(), "staff-admin", "platform.admin")
	if err := f.service.Delete(ctx, admin, "r", other.Ticket.ID); err != nil {
		t.Fatalf("platform admin delete = %v", err)
	}
}
