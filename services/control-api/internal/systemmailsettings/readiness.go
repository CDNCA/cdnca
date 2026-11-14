package systemmailsettings

import (
	"strings"

	"github.com/cdnca/cdnca/libs/mail"
)

// CodeConfigIncomplete is the test mail result when the page lacks what the
// chosen sender needs; TestResult.Missing names the fields.
const CodeConfigIncomplete = "config_incomplete"

// MissingError is returned by a TestSender when the page's
// chosen sender is not complete. Fields are save body paths.
type MissingError struct{ Fields []string }

func (failure *MissingError) Error() string {
	return "system mail settings incomplete: " + strings.Join(failure.Fields, ",")
}

// SMTPSender is the SMTP envelope sender: value.smtp_from, else the SMTP user
// when it is an address, else the environment sender ("" when none fits).
func SMTPSender(value Settings, environment string) string {
	switch {
	case value.SMTPFrom != "":
		return value.SMTPFrom
	case mail.ValidAddress(value.SMTPUser):
		return value.SMTPUser
	case mail.ValidAddress(environment):
		return environment
	}
	return ""
}
