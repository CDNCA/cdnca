package notification

import (
	"net/mail"
	"regexp"
	"strings"
	"time"
)

var observationEmailDomain = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
var observationPhone = regexp.MustCompile(`^\+?[1-9][0-9]{6,14}$`)

// DispatchObservation contains only a masked contact and the local provider
// invocation time. It never contains message content or a recipient credential.
type DispatchObservation struct {
	recipientAddressMasked string
	providerCallStartedAt  time.Time
}

func NewDispatchObservation(channel Channel, contact string, startedAt time.Time) *DispatchObservation {
	if startedAt.IsZero() || startedAt.Year() < 1 || startedAt.Year() > 9999 {
		return nil
	}
	return &DispatchObservation{recipientAddressMasked: maskDispatchContact(channel, contact),
		providerCallStartedAt: startedAt.UTC().Truncate(time.Microsecond)}
}

func maskDispatchContact(channel Channel, contact string) string {
	switch channel {
	case ChannelEmail:
		if len(contact) > 254 || strings.ContainsAny(contact, " \t\r\n\"\\<>") || strings.Count(contact, "@") != 1 {
			return ""
		}
		for index := 0; index < len(contact); index++ {
			if contact[index] < 0x21 || contact[index] > 0x7e {
				return ""
			}
		}
		address, err := mail.ParseAddress(contact)
		local, domain, ok := strings.Cut(contact, "@")
		if err != nil || address.Address != contact || !ok || len(local) > 64 || !observationEmailDomain.MatchString(domain) {
			return ""
		}
		prefix := ""
		if len(local) > 1 && (local[0] >= 'a' && local[0] <= 'z' || local[0] >= 'A' && local[0] <= 'Z' || local[0] >= '0' && local[0] <= '9') {
			prefix = local[:1]
		}
		return prefix + "***@" + domain
	case ChannelSMS:
		if observationPhone.MatchString(contact) {
			return "***" + contact[len(contact)-4:]
		}
	}
	return ""
}
