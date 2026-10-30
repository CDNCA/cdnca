package tickets

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// overdueRequestID marks the notification audit of a reminder raised by the
// background job (no staff or customer acted).
const overdueRequestID = "ticket-sla-reminder"

// remindOneOverdue (fix-ticket2, 546) takes the oldest active ticket still
// waiting for its first staff reply past ResponseSLA that was never
// reminded, marks it reminded and tells the ticket staff
// (ticket.staff.overdue, each under their own subscription). It returns
// false when none is left. SKIP LOCKED lets replicas share the work; a staff
// reply racing it holds the row and is simply not reminded.
func (service *Service) remindOneOverdue(ctx context.Context, tx pgx.Tx, now time.Time) (bool, error) {
	var id, scope, user uuid.UUID
	var ticketNo int64
	var subject, status, username string
	var site *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT t.id,t.tenant_scope_id,t.user_id,t.ticket_no,t.subject,t.status,t.site_id,account.username
		FROM tickets t JOIN users account ON account.id=t.user_id
		WHERE t.first_response_at IS NULL AND t.sla_reminded_at IS NULL AND t.deleted_at IS NULL
		  AND t.status IN ('open','processing') AND t.created_at < $1
		ORDER BY t.created_at,t.id LIMIT 1 FOR UPDATE OF t SKIP LOCKED`, now.Add(-ResponseSLA)).
		Scan(&id, &scope, &user, &ticketNo, &subject, &status, &site, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE tickets SET sla_reminded_at=$2 WHERE id=$1`, id, now); err != nil {
		return false, err
	}
	service.notifyStaff(ctx, tx, scope, EventStaffOverdue, notice{ticketID: id, siteID: site, ticketNo: ticketNo,
		subject: subject, status: status, sourceID: id.String() + ":overdue", requestID: overdueRequestID,
		username: username})
	return true, nil
}

// RemindOverdue sends up to limit overdue reminders, one transaction each.
func (service *Service) RemindOverdue(ctx context.Context, limit int) (int, error) {
	sent := 0
	for sent < limit {
		var done bool
		err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
			var err error
			done, err = service.remindOneOverdue(ctx, tx, service.clock())
			return err
		})
		if err != nil || !done {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// RunOverdueReminders checks for overdue tickets every interval until ctx ends.
func (service *Service) RunOverdueReminders(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if sent, err := service.RemindOverdue(ctx, 200); err != nil && ctx.Err() == nil {
			service.logf("ticket overdue reminders: %v", err)
		} else if sent > 0 {
			service.logf("ticket overdue reminders sent for %d tickets", sent)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
