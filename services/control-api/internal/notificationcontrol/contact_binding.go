package notificationcontrol

import (
	"context"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Contact binding: a subscription response says
// whether the member's own email / phone can receive the channel, so the page
// can warn "subscribed but no email bound". The rule matches the delivery
// resolver (cmd/control-api notification_runtime_open.go): an empty or
// malformed address is recipient_unavailable there and unbound here.
func contactBound(email, phone *string) (bool, bool) {
	return email != nil && validMailbox(*email), phone != nil && validPhone(*phone)
}

func validMailbox(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.ContainsRune(value, '@') &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func validPhone(value string) bool {
	if len(value) < 6 || len(value) > 21 || strings.TrimSpace(value) != value || value == "+" {
		return false
	}
	for index, character := range value {
		if character == '+' && index == 0 {
			continue
		}
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// readContactBinding reads the actor's own contact columns (read only, no
// address leaves this function).
func readContactBinding(ctx context.Context, tx pgx.Tx, actor Actor, result *Subscription) error {
	var email, phone *string
	if err := tx.QueryRow(ctx, `SELECT email,phone FROM users WHERE id=$1`, actor.UserID).Scan(&email, &phone); err != nil {
		return err
	}
	emailBound, phoneBound := contactBound(email, phone)
	result.EmailBound, result.PhoneBound = &emailBound, &phoneBound
	return nil
}
