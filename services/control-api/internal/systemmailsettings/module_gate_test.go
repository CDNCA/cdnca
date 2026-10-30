package systemmailsettings

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Choosing an official mail service needs its module; SMTP, plugins and the
// provider already saved are never asked (RevokeKeepExisting: a saved choice
// stays saved, its sends are gated on the send path).
func TestCheckMailModule(t *testing.T) {
	var asked []string
	granted := map[string]bool{"module.mail.aliyun": true}
	service := (&Service{}).WithModuleGate(func(_ context.Context, _ pgx.Tx, module string) (bool, error) {
		asked = append(asked, module)
		return granted[module], nil
	})
	cases := []struct {
		provider, stored string
		want             error
	}{
		{"", "", nil}, {"smtp", "sendgrid", nil}, {"plugin:com.example.mail", "", nil},
		{"aliyun", "", nil}, {"sendgrid", "", ErrModuleNotLicensed}, {"sendgrid", "aliyun", ErrModuleNotLicensed},
		{"sendgrid", "sendgrid", nil},
	}
	for _, tc := range cases {
		if err := service.checkMailModule(t.Context(), nil, tc.provider, tc.stored); !errors.Is(err, tc.want) && err != tc.want {
			t.Errorf("checkMailModule(%q, stored %q) = %v, want %v", tc.provider, tc.stored, err, tc.want)
		}
	}
	if len(asked) != 3 || asked[0] != "module.mail.aliyun" || asked[1] != "module.mail.sendgrid" {
		t.Errorf("asked %v", asked)
	}
	failing := (&Service{}).WithModuleGate(func(context.Context, pgx.Tx, string) (bool, error) { return false, errors.New("x") })
	if err := failing.checkMailModule(t.Context(), nil, "aliyun", ""); !errors.Is(err, ErrUnavailable) {
		t.Errorf("lease error = %v, want ErrUnavailable", err)
	}
	if err := (&Service{}).checkMailModule(t.Context(), nil, "sendgrid", ""); err != nil {
		t.Errorf("ungated = %v", err)
	}
}
