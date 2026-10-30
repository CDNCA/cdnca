package notification

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"text/template/parse"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

var (
	templateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
	variablePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

const announcementPublishedTemplateID = "announcement_published"

type compiledTemplate struct {
	subject   *template.Template
	body      *template.Template
	variables map[string]struct{}
}

type Catalog struct {
	mu        sync.RWMutex
	templates map[TemplateRef]*compiledTemplate
}

func NewCatalog() *Catalog {
	return &Catalog{templates: make(map[TemplateRef]*compiledTemplate)}
}

func (c *Catalog) Register(definition TemplateDefinition) error {
	compiled, err := compileTemplate(definition)
	if err != nil {
		return err
	}
	if c == nil {
		return ErrInvalidTemplate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.templates == nil {
		c.templates = make(map[TemplateRef]*compiledTemplate)
	}
	if _, exists := c.templates[definition.Ref]; exists {
		return ErrTemplateExists
	}
	c.templates[definition.Ref] = compiled
	return nil
}

func (c *Catalog) Render(ref TemplateRef, context TemplateContext) (RenderedMessage, error) {
	return c.render(ref, context, ContextValidationPolicy{})
}

func (c *Catalog) render(
	ref TemplateRef,
	context TemplateContext,
	policy ContextValidationPolicy,
) (RenderedMessage, error) {
	if c == nil {
		return RenderedMessage{}, ErrTemplateNotFound
	}
	c.mu.RLock()
	compiled := c.templates[ref]
	c.mu.RUnlock()
	if compiled == nil {
		return RenderedMessage{}, ErrTemplateNotFound
	}

	if !validContextValidationPolicyForTemplate(policy, ref) {
		return RenderedMessage{}, ErrContextLimit
	}
	values, err := checkedContext(compiled.variables, context, policy)
	if err != nil {
		return RenderedMessage{}, err
	}
	message := RenderedMessage{Ref: ref}
	if compiled.subject != nil {
		message.Subject, err = executeTemplate(compiled.subject, values, MaxEmailSubjectRunes*utf8.UTFMax)
		if err != nil {
			return RenderedMessage{}, err
		}
		if utf8.RuneCountInString(message.Subject) > MaxEmailSubjectRunes {
			return RenderedMessage{}, ErrRenderLimit
		}
	}
	bodyLimit := MaxEmailBodyBytes
	if ref.Channel == ChannelSMS {
		bodyLimit = MaxSMSBodyBytes
	}
	message.Body, err = executeTemplate(compiled.body, values, bodyLimit)
	if err != nil {
		return RenderedMessage{}, err
	}
	if (ref.Channel == ChannelSMS && len(message.Body) > MaxSMSBodyBytes) ||
		(ref.Channel == ChannelEmail && len(message.Body) > MaxEmailBodyBytes) {
		return RenderedMessage{}, ErrRenderLimit
	}
	return message, nil
}

func compileTemplate(definition TemplateDefinition) (*compiledTemplate, error) {
	// fix-fielderr-be5: each refusal names the request field it is about
	// (template_id, subject, body, variables[n]); errors.Is still sees
	// ErrInvalidTemplate / ErrTemplateLimit.
	if !validTemplateRef(definition.Ref) {
		return nil, fielderr.New(ErrInvalidTemplate, "template_id", fielderr.InvalidFormat)
	}
	switch {
	case definition.Ref.Channel == ChannelEmail && definition.Subject == "":
		return nil, fielderr.New(ErrInvalidTemplate, "subject", fielderr.Required)
	case definition.Ref.Channel == ChannelSMS && definition.Subject != "":
		return nil, fielderr.New(ErrInvalidTemplate, "subject", fielderr.Invalid)
	case definition.Body == "":
		return nil, fielderr.New(ErrInvalidTemplate, "body", fielderr.Required)
	}
	if err := templateSourceSizeError(definition); err != nil {
		return nil, err
	}
	if len(definition.Variables) > MaxTemplateVariables {
		return nil, fielderr.New(ErrTemplateLimit, "variables", fielderr.TooLong)
	}
	variables := make(map[string]struct{}, len(definition.Variables))
	for index, name := range definition.Variables {
		field := fmt.Sprintf("variables[%d]", index)
		if !variablePattern.MatchString(name) {
			return nil, fielderr.New(ErrInvalidTemplate, field, fielderr.InvalidFormat)
		}
		if isSensitiveName(name) {
			return nil, fielderr.New(ErrInvalidTemplate, field, fielderr.Invalid)
		}
		if _, duplicate := variables[name]; duplicate {
			return nil, fielderr.New(ErrInvalidTemplate, field, fielderr.Duplicate)
		}
		variables[name] = struct{}{}
	}

	bodyUsed := make(map[string]struct{}, len(variables))
	body, err := parseTemplatePart("body", definition.Body, bodyUsed)
	if err != nil {
		return nil, fielderr.New(ErrInvalidTemplate, "body", fielderr.Invalid)
	}
	subjectUsed := make(map[string]struct{}, len(variables))
	var subject *template.Template
	if definition.Subject != "" {
		subject, err = parseTemplatePart("subject", definition.Subject, subjectUsed)
		if err != nil {
			return nil, fielderr.New(ErrInvalidTemplate, "subject", fielderr.Invalid)
		}
	}
	// Every variable the template uses must be declared. A declared variable
	// may go unused: an SMS template shares its email sibling's context (one
	// declaration list per event) but says less; Render still requires the
	// context to match the declaration exactly.
	for field, used := range map[string]map[string]struct{}{"body": bodyUsed, "subject": subjectUsed} {
		for name := range used {
			if _, declared := variables[name]; !declared {
				return nil, fielderr.New(ErrInvalidTemplate, field, fielderr.Invalid)
			}
		}
	}
	return &compiledTemplate{subject: subject, body: body, variables: variables}, nil
}

func parseTemplatePart(name, source string, used map[string]struct{}) (*template.Template, error) {
	parsed, err := template.New(name).Option("missingkey=error").Parse(source)
	if err != nil || len(parsed.Templates()) != 1 || parsed.Tree == nil || parsed.Tree.Root == nil {
		return nil, ErrInvalidTemplate
	}
	if err := inspectNode(parsed.Tree.Root, used); err != nil {
		return nil, ErrInvalidTemplate
	}
	return parsed, nil
}

func inspectNode(node parse.Node, used map[string]struct{}) error {
	switch current := node.(type) {
	case *parse.ListNode:
		for _, child := range current.Nodes {
			if err := inspectNode(child, used); err != nil {
				return err
			}
		}
		return nil
	case *parse.TextNode, *parse.CommentNode:
		return nil
	case *parse.ActionNode:
		return inspectPipe(current.Pipe, used)
	case *parse.IfNode:
		if err := inspectPipe(current.Pipe, used); err != nil {
			return err
		}
		if err := inspectNode(current.List, used); err != nil {
			return err
		}
		if current.ElseList != nil {
			return inspectNode(current.ElseList, used)
		}
		return nil
	default:
		return ErrInvalidTemplate
	}
}

func inspectPipe(pipe *parse.PipeNode, used map[string]struct{}) error {
	if pipe == nil || len(pipe.Decl) != 0 || pipe.IsAssign {
		return ErrInvalidTemplate
	}
	for _, command := range pipe.Cmds {
		for _, argument := range command.Args {
			switch value := argument.(type) {
			case *parse.FieldNode:
				if len(value.Ident) != 1 || !variablePattern.MatchString(value.Ident[0]) {
					return ErrInvalidTemplate
				}
				used[value.Ident[0]] = struct{}{}
			case *parse.IdentifierNode:
				if !allowedFunction(value.Ident) {
					return ErrInvalidTemplate
				}
			case *parse.StringNode, *parse.NumberNode, *parse.BoolNode, *parse.NilNode:
			case *parse.PipeNode:
				if err := inspectPipe(value, used); err != nil {
					return err
				}
			default:
				return ErrInvalidTemplate
			}
		}
	}
	return nil
}

func allowedFunction(name string) bool {
	switch name {
	case "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge", "len",
		"print", "printf", "println", "html", "js", "urlquery":
		return true
	default:
		return false
	}
}

func checkedContext(
	expected map[string]struct{},
	context TemplateContext,
	policy ContextValidationPolicy,
) (map[string]string, error) {
	if policy.kind == contextValidationAnnouncementPublishedEmail &&
		(len(expected) != 2 || !hasName(expected, "title") || !hasName(expected, "body")) {
		return nil, ErrVariableMismatch
	}
	if err := validateContextResourcesWithPolicy(context, policy); err != nil {
		return nil, err
	}
	if len(context) != len(expected) {
		return nil, ErrVariableMismatch
	}
	values := make(map[string]string, len(context))
	for name := range expected {
		value, exists := context[name]
		if !exists {
			return nil, ErrVariableMismatch
		}
		values[name] = value.value
	}
	return values, nil
}

func validateContextResources(context TemplateContext) error {
	return validateContextResourcesWithPolicy(context, ContextValidationPolicy{})
}

func validateContextResourcesWithPolicy(context TemplateContext, policy ContextValidationPolicy) error {
	if len(context) > MaxTemplateVariables {
		return ErrContextLimit
	}
	for _, value := range context {
		if value.sensitive {
			return ErrSensitiveContext
		}
	}
	contextBytes := 0
	for name, value := range context {
		maxValueBytes := MaxVariableValueBytes
		if policy.kind == contextValidationAnnouncementPublishedEmail {
			switch name {
			case "title":
				maxValueBytes = MaxEmailSubjectRunes * utf8.UTFMax
			case "body":
				maxValueBytes = MaxEmailBodyBytes
			}
		}
		if !utf8.ValidString(value.value) || len(value.value) > maxValueBytes {
			return ErrContextLimit
		}
		contextBytes += len(name) + len(value.value)
		maxContextBytes := MaxContextBytes
		if policy.kind == contextValidationAnnouncementPublishedEmail {
			maxContextBytes = MaxEmailBodyBytes + MaxEmailSubjectRunes*utf8.UTFMax + len("title") + len("body")
		}
		if contextBytes > maxContextBytes {
			return ErrContextLimit
		}
	}
	return nil
}

func AnnouncementPublishedEmailContextValidationPolicy(ref TemplateRef) (ContextValidationPolicy, error) {
	if !validTemplateRef(ref) || ref.ID != announcementPublishedTemplateID || ref.Channel != ChannelEmail {
		return ContextValidationPolicy{}, ErrContextLimit
	}
	return ContextValidationPolicy{kind: contextValidationAnnouncementPublishedEmail, template: ref}, nil
}

func AnnouncementPublishedEmailContext(title, body string) TemplateContext {
	return TemplateContext{"title": PublicValue(title), "body": PublicValue(body)}
}

func validateContextValidationPolicies(
	eventType string,
	templates map[Channel]TemplateRef,
	contexts map[Channel]TemplateContext,
	policies map[Channel]ContextValidationPolicy,
) error {
	for channel, policy := range policies {
		ref, hasTemplate := templates[channel]
		_, hasContext := contexts[channel]
		if eventType != "announcement.published" || channel != ChannelEmail || !hasTemplate || !hasContext ||
			!validContextValidationPolicyForTemplate(policy, ref) || policy.kind == 0 {
			return ErrContextLimit
		}
	}
	return nil
}

func validContextValidationPolicyForTemplate(policy ContextValidationPolicy, ref TemplateRef) bool {
	if policy == (ContextValidationPolicy{}) {
		return true
	}
	return policy.kind == contextValidationAnnouncementPublishedEmail &&
		policy.template == ref && ref.ID == announcementPublishedTemplateID && ref.Channel == ChannelEmail
}

func hasName(names map[string]struct{}, name string) bool {
	_, exists := names[name]
	return exists
}

func executeTemplate(compiled *template.Template, context map[string]string, maxBytes int) (string, error) {
	output := limitedBuffer{remaining: maxBytes}
	if err := compiled.Execute(&output, context); err != nil {
		if errors.Is(err, ErrRenderLimit) {
			return "", ErrRenderLimit
		}
		return "", ErrRender
	}
	return output.String(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.remaining {
		return 0, ErrRenderLimit
	}
	written, err := b.Buffer.Write(value)
	b.remaining -= written
	return written, err
}

// templateSourceSizeError: invalid UTF-8 or a source over its byte limit
// (ErrTemplateLimit, located on subject or body).
func templateSourceSizeError(definition TemplateDefinition) error {
	if !utf8.ValidString(definition.Subject) {
		return fielderr.New(ErrTemplateLimit, "subject", fielderr.Invalid)
	}
	if !utf8.ValidString(definition.Body) {
		return fielderr.New(ErrTemplateLimit, "body", fielderr.Invalid)
	}
	bodyLimit := MaxEmailBodySourceBytes
	if definition.Ref.Channel == ChannelSMS {
		bodyLimit = MaxSMSBodySourceBytes
	} else if len(definition.Subject) > MaxEmailSubjectSourceBytes {
		return fielderr.New(ErrTemplateLimit, "subject", fielderr.TooLong)
	}
	if len(definition.Body) > bodyLimit {
		return fielderr.New(ErrTemplateLimit, "body", fielderr.TooLong)
	}
	return nil
}

func validTemplateRef(ref TemplateRef) bool {
	return templateIDPattern.MatchString(ref.ID) && ref.Version > 0 &&
		(ref.Channel == ChannelSMS || ref.Channel == ChannelEmail)
}

func isSensitiveName(name string) bool {
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(name))
	for _, marker := range []string{
		"secret", "password", "passwd", "token", "credential", "authorization", "cookie", "privatekey", "apikey", "otp",
	} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}
