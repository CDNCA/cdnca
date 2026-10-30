package notification

import "testing"

// A member who never chose gets every
// channel of a supported tenant event; platform-side events (staff tickets,
// node, market) keep the event policy defaults unchanged.
func TestDefaultChannelsTurnTenantEventsOn(t *testing.T) {
	for _, item := range []struct {
		event                   string
		supported               bool
		defaultSMS, defaultMail bool
		wantSMS, wantMail       bool
	}{
		{"package.monitor.traffic.triggered", true, false, false, true, true},
		{"certificate.expiring", true, false, true, true, true},
		{"announcement.published", true, false, false, true, true},
		{"ticket.replied", true, false, true, true, true},
		// An event the platform has not made subscribable stays off.
		{"package.monitor.cc_rule_auto_switch", false, false, false, false, false},
		// Staff and platform events keep their policy defaults.
		{"ticket.staff.created", true, false, true, false, true},
		{"ticket.staff.overdue", true, false, true, false, true},
		{EventTypeNodeOffline, true, false, false, false, false},
	} {
		sms, mail := DefaultChannels(item.event, item.supported, item.defaultSMS, item.defaultMail)
		if sms != item.wantSMS || mail != item.wantMail {
			t.Errorf("DefaultChannels(%s, supported=%v) = %v/%v, want %v/%v",
				item.event, item.supported, sms, mail, item.wantSMS, item.wantMail)
		}
	}
}
