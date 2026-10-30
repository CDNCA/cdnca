package notification

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be5: a refused template names the request field (template_id,
// subject, body, variables[n]) and still unwraps to the old sentinel.
func TestTemplateRefusalsLocateField(t *testing.T) {
	email := func(subject, body string, variables ...string) TemplateDefinition {
		return TemplateDefinition{Ref: TemplateRef{ID: "site_ready", Version: 1, Channel: ChannelEmail}, Subject: subject, Body: body, Variables: variables}
	}
	sms := func(subject, body string, variables ...string) TemplateDefinition {
		return TemplateDefinition{Ref: TemplateRef{ID: "site_ready", Version: 1, Channel: ChannelSMS}, Subject: subject, Body: body, Variables: variables}
	}
	tooMany := make([]string, MaxTemplateVariables+1)
	for index := range tooMany {
		tooMany[index] = "v" + strings.Repeat("a", index+1)
	}
	for name, check := range map[string]struct {
		definition    TemplateDefinition
		base          error
		field, reason string
	}{
		"template id":         {TemplateDefinition{Ref: TemplateRef{ID: "Bad ID", Version: 1, Channel: ChannelSMS}, Body: "x"}, ErrInvalidTemplate, "template_id", fielderr.InvalidFormat},
		"email subject empty": {email("", "body"), ErrInvalidTemplate, "subject", fielderr.Required},
		"sms subject":         {sms("subject", "body"), ErrInvalidTemplate, "subject", fielderr.Invalid},
		"body empty":          {sms("", ""), ErrInvalidTemplate, "body", fielderr.Required},
		"subject too long":    {email(strings.Repeat("a", MaxEmailSubjectSourceBytes+1), "body"), ErrTemplateLimit, "subject", fielderr.TooLong},
		"email body too long": {email("s", strings.Repeat("a", MaxEmailBodySourceBytes+1)), ErrTemplateLimit, "body", fielderr.TooLong},
		"sms body too long":   {sms("", strings.Repeat("a", MaxSMSBodySourceBytes+1)), ErrTemplateLimit, "body", fielderr.TooLong},
		"body not utf8":       {sms("", string([]byte{0xff})), ErrTemplateLimit, "body", fielderr.Invalid},
		"too many variables":  {email("s", "b", tooMany...), ErrTemplateLimit, "variables", fielderr.TooLong},
		"variable name":       {email("s", "b", "title", "Bad"), ErrInvalidTemplate, "variables[1]", fielderr.InvalidFormat},
		"sensitive variable":  {email("s", "b", "api_token"), ErrInvalidTemplate, "variables[0]", fielderr.Invalid},
		"duplicate variable":  {email("s", "b", "title", "title"), ErrInvalidTemplate, "variables[1]", fielderr.Duplicate},
		"body syntax":         {email("s", "{{.title", "title"), ErrInvalidTemplate, "body", fielderr.Invalid},
		"subject syntax":      {email("{{.title", "b", "title"), ErrInvalidTemplate, "subject", fielderr.Invalid},
		"body undeclared":     {email("{{.title}}", "{{.body}}", "title"), ErrInvalidTemplate, "body", fielderr.Invalid},
		"subject undeclared":  {email("{{.title}}", "{{.body}}", "body"), ErrInvalidTemplate, "subject", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			err := NewCatalog().Register(check.definition)
			if !errors.Is(err, check.base) {
				t.Fatalf("error = %v, want %v", err, check.base)
			}
			located, ok := fielderr.As(err)
			if !ok || located.Field != check.field || located.Reason != check.reason {
				t.Fatalf("located = %+v (%v), want %s/%s", located, err, check.field, check.reason)
			}
		})
	}
	if err := NewCatalog().Register(email("{{.title}}", "{{.body}}", "title", "body")); err != nil {
		t.Fatalf("valid template = %v", err)
	}
}
